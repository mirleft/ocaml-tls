
open Lwt

module Make (TCP: V1_LWT.TCPV4) (E : V1_LWT.ENTROPY) = struct

  module TCP = TCP
  type error = TCP.error

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
    tcp            : TCP.flow ;
    tracer         : tracer option ;
    mutable state  : [ `Active of Tls.Engine.state
                     | `Eof
                     | `Error of error ] ;
    mutable linger : Cstruct.t list ;
  }

  let error e = return (`Error e)
  let return_ok = return (`Ok ())

  let error_of_alert alert =
    `Unknown (Tls.Packet.alert_type_to_string alert)

  let list_of_option = function None -> [] | Some x -> [x]

  let check_write flow res =
    ( match (flow.state, res) with
      | (`Active _, (`Eof | `Error _ as e)) ->
          flow.state <- e ; TCP.close flow.tcp
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
            | `Alert alert -> `Error (error_of_alert alert) );
          ( match resp with
            | None     -> return_ok
            | Some buf -> TCP.write flow.tcp buf >>= check_write flow ) >>
          ( match res with
            | `Ok _ -> return_unit
            | _     -> TCP.close flow.tcp ) >>
          return (`Ok data)
      | `Fail (alert, `Response resp) ->
          let reason = `Error (error_of_alert alert) in
          flow.state <- reason ;
          TCP.(write flow.tcp resp >> close flow.tcp) >> return reason
    in
    match flow.state with
    | `Eof | `Error _ as e -> return e
    | `Active tls          ->
        TCP.read flow.tcp >>= function
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
            TCP.write flow.tcp answer >>= check_write flow
        | None ->
            (* "Impossible" due to handhake draining. *)
            error (`Unknown "tls: write: flow not ready to send")

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
        | `Error e -> return (`Error e)
        | `Eof     -> return (`Error (`Unknown "tls: end_of_file in handshake"))

  let reneg flow =
    match flow.state with
    | `Eof | `Error _ as e -> return e
    | `Active tls ->
        match tracing flow @@ fun () -> Tls.Engine.reneg tls with
        | None             -> return (`Error (`Unknown "renegotiation in progress"))
        | Some (tls', buf) ->
            flow.state <- `Active tls' ;
            TCP.write flow.tcp buf

  let close flow =
    match flow.state with
    | `Active tls ->
      flow.state <- `Eof ;
      let (_, buf) = tracing flow @@ fun () ->
        Tls.Engine.send_close_notify tls in
      TCP.(write flow.tcp buf >> close flow.tcp)
    | _           -> return_unit

  let client_of_tcp_flow ?trace conf host flow =
    let (tls, init) = Tls.Engine.client conf in
    let tls_flow = {
      role   = `Client ;
      tcp    = flow ;
      state  = `Active tls ;
      linger = [] ;
      tracer = trace ;
    } in
    TCP.write flow init >> drain_handshake tls_flow

  let server_of_tcp_flow ?trace conf flow =
    let tls_flow = {
      role   = `Server ;
      tcp    = flow ;
      state  = `Active (Tls.Engine.server conf) ;
      linger = [] ;
      tracer = trace ;
    } in
    drain_handshake tls_flow

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

(* Mock-`FLOW` module, for constructing a `Channel` on top of. *)
module Make_flow (TCP: V1_LWT.TCPV4) (E : V1_LWT.ENTROPY) = struct

  include Make (TCP) (E)

  type t = unit

  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  type callback = flow -> unit io

  type ipv4input = unit
  type ipv4addr  = Ipaddr.V4.t
  type ipv4      = unit

  let lament = "not implemented"
  let nope   = fail (Failure lament)

  let write_nodelay _ _     = nope
  and writev_nodelay _ _    = nope
  and create_connection _ _ = nope
  and disconnect _          = nope
  and connect _             = nope
  and input _ ~listeners    = failwith lament
  and get_dest _            = failwith lament

  and id _ = assert false
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
