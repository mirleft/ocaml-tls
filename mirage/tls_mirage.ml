open Lwt
open Nocrypto

open Result

module Make (F : V1_LWT.FLOW) = struct

  module FLOW = F

  type tls_error = [
    | `Tls_alert   of Tls.Packet.alert_type
    | `Tls_failure of Tls.Engine.failure
  ]

  type error  = [ tls_error
                | `Msg of string
                | `Flow of FLOW.error ]
  type write_error = [ tls_error
                     | `Closed
                     | `Msg of string
                     | `Flow of FLOW.write_error ]
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t


  let pp_tls_error pp = function
    | `Tls_failure f -> Format.fprintf pp "%s" (Tls.Engine.string_of_failure f)
    | `Tls_alert a -> Format.fprintf  pp "%s" (Tls.Packet.alert_type_to_string a)

  let pp_error pp = function
    | #tls_error as e -> pp_tls_error pp e
    | `Flow e -> FLOW.pp_error pp e
    | `Msg e -> Format.fprintf pp "%s" e

  let pp_write_error pp = function
    | #tls_error as e -> pp_tls_error pp e
    | `Flow e -> FLOW.pp_write_error pp e
    | `Msg e -> Format.fprintf pp "%s" e
    | `Closed -> Format.fprintf pp "closed"

  type tracer = Sexplib.Sexp.t -> unit

  type flow = {
    role           : [ `Server | `Client ] ;
    flow           : FLOW.flow ;
    tracer         : tracer option ;
    mutable state  : [ `Active of Tls.Engine.state | `Eof | `Error of tls_error ] ;
    mutable linger : Cstruct.t list ;
  }

  let list_of_option = function None -> [] | Some x -> [x]

  let check_write flow (res : (unit, FLOW.write_error) result) =
    match flow.state, res with
    | `Active _, Error `Closed -> flow.state <- `Eof ; FLOW.close flow.flow
    | `Active _, Error (`Msg m) -> flow.state <- `Eof ; FLOW.close flow.flow
    | _ -> return_unit

  let tracing flow f =
    match flow.tracer with
    | None      -> f ()
    | Some hook -> Tls.Tracing.active ~hook f

  let lift_tls_err : tls_error -> [ error | `Closed ] = function
    | `Tls_failure x -> `Tls_failure x
    | `Tls_alert x -> `Tls_alert x

  let read_react flow : (Cstruct.t option, [ error | `Closed ]) result Lwt.t =
    let handle tls buf =
      match
        tracing flow @@ fun () -> Tls.Engine.handle_tls tls buf
      with
      | `Ok (res, `Response resp, `Data data) ->
          flow.state <- ( match res with
            | `Ok tls      -> `Active tls
            | `Eof         -> `Eof
            | `Alert alert -> `Error (`Tls_alert alert) );
          ( match resp with
            | None     -> Lwt.return_unit
            | Some buf -> FLOW.write flow.flow buf >>= check_write flow ) >>= fun () ->
          ( match res with
            | `Ok _ -> return_unit
            | _     -> FLOW.close flow.flow ) >>= fun () ->
          return (Ok data)
      | `Fail (fail, `Response resp) ->
          let reason = `Tls_failure fail in
          flow.state <- `Error reason ;
          FLOW.(write flow.flow resp >>= fun _ -> close flow.flow) >|= fun () -> Error reason
    in
    match flow.state with
    | `Eof -> return (Error `Closed)
    | `Error e -> return (Error (lift_tls_err e))
    | `Active _ ->
      FLOW.read flow.flow >>= function
      | Ok `Eof -> flow.state <- `Eof ; return (Error `Closed)
      | Error e -> flow.state <- `Eof ; return (Error (`Flow e))
      | Ok (`Data buf) -> match flow.state with
        | `Active tls -> handle tls buf
        | `Eof -> return (Error `Closed)
        | `Error e -> return (Error (lift_tls_err e))

  let rec read flow =
    match flow.linger with
    | [] ->
      ( read_react flow >>= function
          | Ok None       -> read flow
          | Ok (Some buf) -> return (Ok (`Data buf))
          | Error `Closed -> return (Ok `Eof)
          | Error (`Flow x) -> return (Error (`Flow x))
          | Error (`Msg m) -> return (Error (`Msg m))
          | Error (#tls_error as e) -> return (Error e))
    | bufs ->
        flow.linger <- [] ;
        return (Ok (`Data (Tls.Utils.Cs.appends @@ List.rev bufs)))

  let lift_tls_err_w : tls_error -> write_error = function
    | `Tls_alert a -> `Tls_alert a
    | `Tls_failure f -> `Tls_failure f

  let writev flow bufs =
    match flow.state with
    | `Eof -> return (Error `Closed)
    | `Error e -> return (Error (lift_tls_err_w e))
    | `Active tls ->
        match
          tracing flow @@ fun () -> Tls.Engine.send_application_data tls bufs
        with
        | Some (tls, answer) ->
            flow.state <- `Active tls ;
            FLOW.write flow.flow answer >>= fun r -> check_write flow r >|= fun () ->
            ( match r with
              | Ok () -> Ok ()
              | Error e -> Error (`Flow e) )
        | None ->
            (* "Impossible" due to handshake draining. *)
            assert false

  let write flow buf = writev flow [buf]

  let lift_r_to_w : [ error | `Closed ] -> write_error = function
    | #tls_error as e -> e
    | `Msg m -> `Msg m
    | `Closed -> `Closed
    | `Flow (`Msg m) -> `Flow (`Msg m)

  (*
   * XXX bad XXX
   * This is a point that should particularly be protected from concurrent r/w.
   * Doing this before a `t` is returned is safe; redoing it during rekeying is
   * not, as the API client already sees the `t` and can mistakenly interleave
   * writes while this is in progress.
   * *)
  let rec drain_handshake flow =
    match flow.state with
    | `Active tls when Tls.Engine.can_handle_appdata tls -> return (Ok flow)
    | _ ->
      (* read_react re-throws *)
        read_react flow >>= function
        | Ok mbuf ->
          flow.linger <- list_of_option mbuf @ flow.linger ;
          drain_handshake flow
        | Error e -> return (Error (lift_r_to_w e))

  let reneg flow =
    match flow.state with
    | `Eof -> return (Error `Closed)
    | `Error e -> return (Error (lift_tls_err_w e))
    | `Active tls ->
        match tracing flow @@ fun () -> Tls.Engine.reneg tls with
        | None             ->
            (* XXX make this impossible to reach *)
            invalid_arg "Renegotiation already in progress"
        | Some (tls', buf) ->
            flow.state <- `Active tls' ;
            FLOW.write flow.flow buf >>= fun _ ->
            drain_handshake flow >|= function
            | Ok _ -> Ok ()
            | Error e -> Error e

  let close flow =
    match flow.state with
    | `Active tls ->
      flow.state <- `Eof ;
      let (_, buf) = tracing flow @@ fun () ->
        Tls.Engine.send_close_notify tls in
      FLOW.(write flow.flow buf >>= fun _ -> close flow.flow)
    | _           -> return_unit

  let client_of_flow ?trace conf ?host flow =
    let conf' = match host with
      | None -> conf
      | Some host -> Tls.Config.peer conf host
    in
    let (tls, init) = Tls.Engine.client conf' in
    let tls_flow = {
      role   = `Client ;
      flow   = flow ;
      state  = `Active tls ;
      linger = [] ;
      tracer = trace ;
    } in
    FLOW.write flow init >>= fun _ -> drain_handshake tls_flow

  let server_of_flow ?trace conf flow =
    let tls_flow = {
      role   = `Server ;
      flow   = flow ;
      state  = `Active (Tls.Engine.server conf) ;
      linger = [] ;
      tracer = trace ;
    } in
    drain_handshake tls_flow

  let epoch flow =
    match flow.state with
    | `Eof | `Error _ -> Error ()
    | `Active tls     ->
        match Tls.Engine.epoch tls with
        | `InitialEpoch -> assert false (* `drain_handshake` invariant. *)
        | `Epoch e      -> Ok e

(*   let create_connection t tls_params host (addr, port) =
    |+ XXX addr -> (host : string) +|
    TCP.create_connection t (addr, port) >>= function
      | `Error _ as e -> return e
      | `Ok flow      -> client_of_tcp_flow tls_params host flow *)

(*   let listen_ssl t cert ~port callback =
    let cb flow =
      server_of_tcp_flow cert flow >>= callback in
    TCP.input t ~listeners:(fun p -> if p = port then Some cb else None) *)

end

module X509 (KV : V1_LWT.KV_RO) (C : V1.PCLOCK) = struct

  let ca_roots_file = "ca-roots.crt"
  let default_cert  = "server"

  let (>>==) a f =
    a >>= function
      | Ok x -> f x
      | Error `Unknown_key -> fail (Invalid_argument "a required key was missing from the key-value store")
      | Error (`Msg s) -> fail (Invalid_argument s)

  let (>|==) a f = a >>== fun x -> return (f x)

  let read_full kv ~name =
    KV.size kv name    >>==
    KV.read kv name 0L >|== Tls.Utils.Cs.appends

  open X509.Encoding.Pem

  let authenticator kv clock = function
    | `Noop -> return X509.Authenticator.null
    | `CAs  ->
        let time = Ptime.v (C.now_d_ps clock) |> Ptime.to_float_s in
        read_full kv ca_roots_file
        >|= Certificate.of_pem_cstruct
        >|= X509.Authenticator.chain_of_trust ~time

  let certificate kv =
    let read name =
      read_full kv (name ^ ".pem") >|= Certificate.of_pem_cstruct >>= fun certs ->
      (read_full kv (name ^ ".key") >|= fun pem ->
       match Private_key.of_pem_cstruct1 pem with
       | `RSA key -> key) >>= fun pk ->
      return (certs, pk)
    in function | `Default   -> read default_cert
                | `Name name -> read name
end
