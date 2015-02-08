open Lwt
open Nocrypto

module Make (F : V1_LWT.FLOW) (E : V1_LWT.ENTROPY) = struct

  module FLOW = F

  type error  = [ `Tls of string | `Flow of FLOW.error ]
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  module ENTROPY = E
  (*
   * XXX 1: Would be nice if this happened behind the scenes.
   * XXX 2: Would be even nicer if nocrypto did this on its own.
   *)
  let attach_entropy e =
    ENTROPY.handler e Nocrypto.Rng.Accumulator.add_rr

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

  let tls_error e = `Error (`Tls e)
  let tls_alert a = `Error (`Tls (Tls.Packet.alert_type_to_string a))
  let tls_fail f  = `Error (`Tls (Tls.Engine.string_of_failure f))

  let return_error e     = return (`Error e)
  let return_tls_error e = return (tls_error e)
  let return_ok          = return (`Ok ())

  let list_of_option = function None -> [] | Some x -> [x]

  let lift_result = function
    | `Error e          -> `Error (`Flow e)
    | `Eof | `Ok _ as r -> r

  let check_write flow f_res =
    let res = lift_result f_res in
    ( match (flow.state, res) with
      | (`Active _, (`Eof | `Error _ as e)) ->
          flow.state <- e ; FLOW.close flow.flow
      | _ -> return_unit ) >>
    return res

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
            | Some buf -> FLOW.write flow.flow buf >>= check_write flow ) >>
          ( match res with
            | `Ok _ -> return_unit
            | _     -> FLOW.close flow.flow ) >>
          return (`Ok data)
      | `Fail (fail, `Response resp) ->
          let reason = tls_fail fail in
          flow.state <- reason ;
          FLOW.(write flow.flow resp >> close flow.flow) >> return reason
    in
    match flow.state with
    | `Eof | `Error _ as e -> return e
    | `Active tls          ->
        FLOW.read flow.flow >|= lift_result >>= function
          | `Eof | `Error _ as e -> flow.state <- e ; return e
          | `Ok buf              -> handle tls buf

  let rec read flow =
    match flow.linger with
    | [] ->
      ( read_react flow >>= function
          | `Ok None             -> read flow
          | `Ok (Some buf)       -> return (`Ok buf)
          | `Eof | `Error _ as e -> return e )
    | bufs ->
        flow.linger <- [] ;
        return (`Ok (Tls.Utils.Cs.appends @@ List.rev bufs))

  let writev flow bufs =
    match flow.state with
    | `Eof | `Error _ as e -> return e
    | `Active tls ->
        match
          tracing flow @@ fun () -> Tls.Engine.send_application_data tls bufs
        with
        | Some (tls, answer) ->
            flow.state <- `Active tls ;
            FLOW.write flow.flow answer >>= check_write flow
        | None ->
            (* "Impossible" due to handhake draining. *)
            return_tls_error "write: flow not ready to send"

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
        | `Eof     -> return_tls_error "tls: end_of_file in handshake"

  let reneg flow =
    match flow.state with
    | `Eof | `Error _ as e -> return e
    | `Active tls ->
        match tracing flow @@ fun () -> Tls.Engine.reneg tls with
        | None             -> return_tls_error "renegotiation in progress"
        | Some (tls', buf) ->
            flow.state <- `Active tls' ;
            FLOW.write flow.flow buf >|= lift_result

  let close flow =
    match flow.state with
    | `Active tls ->
      flow.state <- `Eof ;
      let (_, buf) = tracing flow @@ fun () ->
        Tls.Engine.send_close_notify tls in
      FLOW.(write flow.flow buf >> close flow.flow)
    | _           -> return_unit

  let client_of_flow ?trace conf host flow =
    let (tls, init) = Tls.Engine.client conf in
    let tls_flow = {
      role   = `Client ;
      flow   = flow ;
      state  = `Active tls ;
      linger = [] ;
      tracer = trace ;
    } in
    FLOW.write flow init >> drain_handshake tls_flow

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
    | `Eof | `Error _ -> `Error
    | `Active tls     ->
        match Tls.Engine.epoch tls with
        | `InitialEpoch -> assert false (* `drain_handshake` invariant. *)
        | `Epoch e      -> `Ok e

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

module X509 (KV : V1_LWT.KV_RO) (C : V1.CLOCK) = struct

  let (</>) p1 p2 = p1 ^ "/" ^ p2

  let path          = "tls"
  let ca_roots_file = path </> "ca-roots.crt"
  let default_cert  = "server"

  let (>>==) a f =
    a >>= function
      | `Ok x -> f x
      | `Error (KV.Unknown_key key) -> fail (Invalid_argument key)

  let (>|==) a f = a >>== fun x -> return (f x)

  let read_full kv ~name =
    KV.size kv name   >|== Int64.to_int >>=
    KV.read kv name 0 >|== Tls.Utils.Cs.appends

  let authenticator kv = function
    | `Noop -> return X509.Authenticator.null
    | `CAs  ->
        let time = C.time () in
        read_full kv ca_roots_file
        >|= X509.Cert.of_pem_cstruct
        >|= X509.Authenticator.chain_of_trust ~time

  let certificate kv =
    let read name =
      lwt certs =
        read_full kv (path </> name ^ ".pem") >|= X509.Cert.of_pem_cstruct
      and pk =
        read_full kv (path </> name ^ ".key") >|= X509.PK.of_pem_cstruct1 in
      return (certs, pk)
    in function | `Default   -> read default_cert
                | `Name name -> read name
end
