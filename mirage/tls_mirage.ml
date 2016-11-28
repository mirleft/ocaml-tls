open Lwt
open Nocrypto

module Make (F : V1_LWT.FLOW) = struct

  module FLOW = F

  type error  = [ `Tls_alert   of Tls.Packet.alert_type
                | `Tls_failure of Tls.Engine.failure
                | `Flow        of [`Read of V1.Flow.error | `Write of V1.Flow.write_error] ]
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  let error_message = function
    | `Tls_failure f -> Tls.Engine.string_of_failure f
    | `Tls_alert a -> Tls.Packet.alert_type_to_string a
    | `Flow (`Read e) -> Format.asprintf "%a" Mirage_pp.pp_flow_error e
    | `Flow (`Write e) -> Format.asprintf "%a" Mirage_pp.pp_flow_write_error e

  type tracer = Sexplib.Sexp.t -> unit

  type flow = {
    role           : [ `Server | `Client ] ;
    flow           : FLOW.flow ;
    tracer         : tracer option ;
    mutable state  : [ `Active of Tls.Engine.state
                     | `Eof
                     | `Error of error ] ;
    mutable linger : Cstruct.t list ;
  }

  let tls_alert a = `Error (`Tls_alert a)
  let tls_fail f  = `Error (`Tls_failure f)

  let return_error e     = return (`Error e)
  let return_ok          = return (`Ok ())

  let list_of_option = function None -> [] | Some x -> [x]

  let check_write flow (f_res : (unit, V1.Flow.write_error) Result.result) :
          [ `Error of [ `Flow of [ `Write of V1.Flow.write_error ] ]
          | `Eof
          | `Ok of unit ] Lwt.t
          =
    let res = match f_res with
    | Ok () -> `Ok ()
    | Error `Closed -> `Eof
    | Error p -> `Error (`Flow (`Write p))
    in
    ( match (flow.state, res) with
      | (`Active _, (`Eof | `Error _ as e)) ->
          flow.state <- e ; FLOW.close flow.flow
      | _ -> return_unit ) >>= fun () ->
    return res

  let flow_result_of_check_write = function
  | `Ok p -> Ok p
  | `Eof -> Error `Closed
  | `Error (`Flow (`Write p)) -> Error p

  let tracing flow f =
    match flow.tracer with
    | None      -> f ()
    | Some hook -> Tls.Tracing.active ~hook f

  let read_react flow =

    let handle tls buf =
      match
        tracing flow @@ fun () -> Tls.Engine.handle_tls tls buf
      with
      | `Ok (res, `Response resp, `Data data) ->
          flow.state <- ( match res with
            | `Ok tls      -> `Active tls
            | `Eof         -> `Eof
            | `Alert alert -> tls_alert alert );
          ( match resp with
            | None     -> return_ok
            | Some buf -> FLOW.write flow.flow buf >>= check_write flow ) >>= fun _ ->
          ( match res with
            | `Ok _ -> return_unit
            | _     -> FLOW.close flow.flow ) >>= fun () ->
          return (`Ok data)
      | `Fail (fail, `Response resp) ->
          let reason = tls_fail fail in
          flow.state <- reason ;
          FLOW.(write flow.flow resp >>= fun _ -> close flow.flow) >>= fun () -> return reason
    in
    let lift_read_result = function
          | Ok (`Data buf) -> `Ok buf
          | Ok `Eof        -> `Eof
          | Error e        -> `Error (`Flow (`Read e))
    in
    match flow.state with
    | `Eof | `Error _ as e -> return e
    | `Active _            ->
        FLOW.read flow.flow >|= lift_read_result
          >>= function
          | `Eof | `Error _ as e -> flow.state <- e ; return e
          | `Ok buf              -> match flow.state with
                                    | `Active tls          -> handle tls buf
                                    | `Eof | `Error _ as e -> return e

  let rec read flow =
    match flow.linger with
    | [] ->
      ( read_react flow >>= function
          | `Ok None                 -> read flow
          | `Ok (Some buf)           -> return (Ok (`Data buf))
          | `Eof                     -> return (Ok `Eof)
          | `Error (`Flow (`Read e)) -> return (Error e))
    | bufs ->
        flow.linger <- [] ;
        return (Ok (`Data (Tls.Utils.Cs.appends @@ List.rev bufs)))

  let writev flow bufs : (unit, V1.Flow.write_error) Result.result Lwt.t =
    match flow.state with
    | `Eof
      -> return @@ flow_result_of_check_write `Eof
    | `Error (`Flow (`Write p)) as e
      -> return @@ flow_result_of_check_write e
    | `Active tls ->
        match
          tracing flow @@ fun () -> Tls.Engine.send_application_data tls bufs
        with
        | Some (tls, answer) ->
            flow.state <- `Active tls ;
            FLOW.write flow.flow answer >>= check_write flow >|= flow_result_of_check_write
        | None ->
            (* "Impossible" due to handshake draining. *)
            assert false

  let write flow buf = writev flow [buf]

  (*
   * XXX bad XXX
   * This is a point that should particularly be protected from concurrent r/w.
   * Doing this before a `t` is returned is safe; redoing it during rekeying is
   * not, as the API client already sees the `t` and can mistakenly interleave
   * writes while this is in progress.
   * *)
  let rec drain_handshake flow =
    match flow.state with
    | `Active tls when Tls.Engine.can_handle_appdata tls ->
        return (`Ok flow)
    | _ ->
      (* read_react re-throws *)
        read_react flow >>= function
        | `Ok mbuf ->
            flow.linger <- list_of_option mbuf @ flow.linger ;
            drain_handshake flow
        | `Error e -> return_error e
        | `Eof     -> return `Eof

  let flow_result_of_drain_handshake = function
    | `Ok _                -> return (Ok ())
    | `Eof -> return @@ Error `Closed
    | `Error (`Flow (`Write e)) -> return @@ Error e

  let reneg flow =
    match flow.state with
    | `Eof -> return @@ Error `Closed
    | `Error (`Flow (`Write e)) -> return @@ Error e
    | `Active tls ->
        match tracing flow @@ fun () -> Tls.Engine.reneg tls with
        | None             ->
            (* XXX make this impossible to reach *)
            invalid_arg "Renegotiation already in progress"
        | Some (tls', buf) ->
            flow.state <- `Active tls' ;
            FLOW.write flow.flow buf >>= fun _ ->
            drain_handshake flow >>= function
            | `Ok _                -> return (Ok ())
            | `Eof -> return @@ Error `Closed
            | `Error (`Flow (`Write e)) -> return @@ Error e

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
    FLOW.write flow init >>= fun _ -> drain_handshake tls_flow >>= function
            | `Ok flow -> return (Ok flow)
            | `Eof -> return @@ Error `Closed
            | `Error (`Flow (`Write e)) -> return @@ Error e

  let server_of_flow ?trace conf flow =
    let tls_flow = {
      role   = `Server ;
      flow   = flow ;
      state  = `Active (Tls.Engine.server conf) ;
      linger = [] ;
      tracer = trace ;
    } in
    drain_handshake tls_flow >>= function
            | `Ok flow -> return (Ok flow)
            | `Eof -> return @@ Error `Closed
            | `Error (`Flow (`Write e)) -> return @@ Error e

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
