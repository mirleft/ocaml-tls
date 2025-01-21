open Lwt.Infix

module Make (F : Mirage_flow.S) = struct

  type error  = [ `Tls_alert   of Tls.Packet.alert_type
                | `Tls_failure of Tls.Engine.failure
                | `Read of F.error
                | `Write of F.write_error ]

  type write_error = [ Mirage_flow.write_error | error ]

  let pp_error ppf = function
    | `Tls_failure f -> Tls.Engine.pp_failure ppf f
    | `Tls_alert a   -> Fmt.string ppf @@ Tls.Packet.alert_type_to_string a
    | `Read  e       -> F.pp_error ppf e
    | `Write e       -> F.pp_write_error ppf e

  let pp_write_error ppf = function
    | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
    | #error as e                   -> pp_error ppf e

  type flow = {
    role           : [ `Server | `Client ] ;
    flow           : F.flow ;
    mutable state  : [ `Active of Tls.Engine.state
                     | `Read_closed of Tls.Engine.state
                     | `Write_closed of Tls.Engine.state
                     | `Closed
                     | `Error of error ] ;
    mutable linger : string list ;
  }

  let half_close state mode =
    match state, mode with
    | `Active tls, `read -> `Read_closed tls
    | `Active tls, `write -> `Write_closed tls
    | `Active _, `read_write -> `Closed
    | `Read_closed tls, `read -> `Read_closed tls
    | `Read_closed _, (`write | `read_write) -> `Closed
    | `Write_closed tls, `write -> `Write_closed tls
    | `Write_closed _, (`read | `read_write) -> `Closed
    | (`Closed | `Error _) as e, (`read | `write | `read_write) -> e

  let inject_state tls = function
    | `Active _ -> `Active tls
    | `Read_closed _ -> `Read_closed tls
    | `Write_closed _ -> `Write_closed tls
    | (`Closed | `Error _) as e -> e

  let tls_alert a = `Error (`Tls_alert a)
  let tls_fail f  = `Error (`Tls_failure f)

  let write_flow flow buf =
    F.write flow.flow (Cstruct.of_string buf) >>= function
    | Ok _ as o -> Lwt.return o
    | Error `Closed ->
      flow.state <- half_close flow.state `write;
      Lwt.return (Error (`Write `Closed))
    | Error e ->
      flow.state <- `Error (`Write e);
      Lwt.return (Error (`Write e))

  let read_react flow =
    let handle tls buf =
      match Tls.Engine.handle_tls tls buf with
      | Ok (state, eof, `Response resp, `Data data) ->
        let state = inject_state state flow.state in
        let state = Option.(value ~default:state (map (fun `Eof -> half_close state `read) eof)) in
        flow.state <- state;
        ( match resp with
          | None     -> Lwt.return @@ Ok ()
          | Some buf -> write_flow flow buf) >>= fun _ ->
        Lwt.return @@ `Ok (Option.map Cstruct.of_string data)
      | Error (fail, `Response resp) ->
        let reason = match fail with
          | `Alert a -> tls_alert a
          | f -> tls_fail f
        in
        flow.state <- reason ;
        F.write flow.flow (Cstruct.of_string resp) >>= fun _ ->
        Lwt.return reason
    in
    match flow.state with
    | `Error _ as e -> Lwt.return e
    | `Read_closed _ | `Closed -> Lwt.return `Eof
    | `Active _ | `Write_closed _ ->
      F.read flow.flow >>= function
      | Error e ->
        flow.state <- `Error (`Read e);
        Lwt.return (`Error (`Read e))
      | Ok `Eof ->
        flow.state <- half_close flow.state `read;
        Lwt.return `Eof
      | Ok `Data buf -> match flow.state with
        | `Active tls | `Write_closed tls -> handle tls (Cstruct.to_string buf)
        | `Read_closed _ | `Closed -> Lwt.return `Eof
        | `Error _ as e -> Lwt.return e

  let rec read flow =
    match flow.linger with
    | [] ->
      ( read_react flow >>= function
          | `Ok None       -> read flow
          | `Ok (Some buf) -> Lwt.return @@ Ok (`Data buf)
          | `Eof           -> Lwt.return @@ Ok `Eof
          | `Error e       -> Lwt.return @@ Error e )
    | bufs ->
      flow.linger <- [] ;
      let str = String.concat "" (List.rev bufs) in
      Lwt.return @@ Ok (`Data (Cstruct.of_string str))

  let writev flow bufs =
    match flow.state with
    | `Closed | `Write_closed _ -> Lwt.return @@ Error `Closed
    | `Error e -> Lwt.return @@ Error (e :> write_error)
    | `Active tls | `Read_closed tls ->
        let bufs = List.map Cstruct.to_string bufs in
        match Tls.Engine.send_application_data tls bufs with
        | Some (tls, answer) ->
            flow.state <- `Active tls ;
            write_flow flow answer
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
    | `Active tls when not (Tls.Engine.handshake_in_progress tls) ->
        Lwt.return @@ Ok flow
    | _ ->
      (* read_react re-throws *)
        read_react flow >>= function
        | `Ok mbuf ->
            flow.linger <- Option.(to_list (map Cstruct.to_string mbuf)) @ flow.linger ;
            drain_handshake flow
        | `Error e -> Lwt.return @@ Error (e :> write_error)
        | `Eof     -> Lwt.return @@ Error `Closed

  type wr_or_msg = [ write_error | `Msg of string ]

  let underlying flow = flow.flow

  let reneg ?authenticator ?acceptable_cas ?cert ?(drop = true) flow =
    match flow.state with
    | `Closed | `Write_closed _ | `Read_closed _ -> Lwt.return @@ Error `Closed
    | `Error e    -> Lwt.return @@ Error (e :> wr_or_msg)
    | `Active tls ->
        match Tls.Engine.reneg ?authenticator ?acceptable_cas ?cert tls with
        | None             -> Lwt.return (Error (`Msg "Renegotiation already in progress"))
        | Some (tls', buf) ->
            if drop then flow.linger <- [] ;
            flow.state <- `Active tls' ;
            write_flow flow buf >>= fun _ ->
            drain_handshake flow >|= function
            | Ok _    -> Ok ()
            | Error e -> Error (e :> wr_or_msg)

  let key_update ?request flow =
    match flow.state with
    | `Closed | `Write_closed _ -> Lwt.return @@ Error `Closed
    | `Error e    -> Lwt.return @@ Error (e :> wr_or_msg)
    | `Active tls | `Read_closed tls ->
      match Tls.Engine.key_update ?request tls with
      | Error _ -> Lwt.return (Error (`Msg "Key update failed"))
      | Ok (tls', buf) ->
        flow.state <- `Active tls' ;
        write_flow flow buf >|= function
        | Ok _ as o -> o
        | Error e   -> Error (e :> wr_or_msg)

  let close flow =
    (match flow.state with
     | `Active tls | `Read_closed tls ->
       let tls, buf = Tls.Engine.send_close_notify tls in
       flow.state <- inject_state tls flow.state;
       flow.state <- `Closed;
       write_flow flow buf >|= fun _ ->
       ()
     | `Write_closed _ ->
       flow.state <- `Closed;
       Lwt.return_unit
     | _ -> Lwt.return_unit) >>= fun () ->
    F.close flow.flow

  let shutdown flow mode =
    match flow.state with
    | `Active tls | `Read_closed tls | `Write_closed tls ->
      let tls, buf =
        match flow.state, mode with
        | (`Active tls | `Read_closed tls), (`write | `read_write) ->
          let tls, buf = Tls.Engine.send_close_notify tls in
          tls, Some buf
        | _, _ -> tls, None
      in
      flow.state <- inject_state tls (half_close flow.state mode);
      (* as outlined above, this may fail since the TCP flow may already be (half-)closed *)
      Option.fold
        ~none:Lwt.return_unit
        ~some:(fun b -> write_flow flow b >|= fun _ -> ())
        buf >>= fun () ->
      (match flow.state with
       | `Closed -> F.close flow.flow
       | _ -> Lwt.return_unit)
    | `Error _ | `Closed ->
      F.close flow.flow

  let client_of_flow conf ?host flow =
    let conf' = match host with
      | None      -> conf
      | Some host -> Tls.Config.peer conf host
    in
    let (tls, init) = Tls.Engine.client conf' in
    let tls_flow = {
      role   = `Client ;
      flow   = flow ;
      state  = `Active tls ;
      linger = [] ;
    } in
    write_flow tls_flow init >>= fun _ ->
    drain_handshake tls_flow

  let server_of_flow conf flow =
    let tls_flow = {
      role   = `Server ;
      flow   = flow ;
      state  = `Active (Tls.Engine.server conf) ;
      linger = [] ;
    } in
    drain_handshake tls_flow

  let epoch flow =
    match flow.state with
    | `Closed | `Error _ -> Error ()
    | `Active tls | `Read_closed tls | `Write_closed tls -> Tls.Engine.epoch tls

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

module X509 (KV : Mirage_kv.RO) = struct

  let ca_roots_file = Mirage_kv.Key.v "ca-roots.crt"
  let default_cert  = "server"

  let err_fail pp = function
    | Ok x -> Lwt.return x
    | Error e -> Fmt.kstr Lwt.fail_with "%a" pp e

  let pp_msg ppf = function `Msg m -> Fmt.string ppf m

  let decode_or_fail f cs = err_fail pp_msg (f cs)

  let read kv name =
    KV.get kv name >>= err_fail KV.pp_error >|= Cstruct.of_string

  let read_crl kv = function
    | None -> Lwt.return None
    | Some filename ->
      read kv (Mirage_kv.Key.v filename) >>= fun data ->
      err_fail pp_msg (X509.CRL.decode_der (Cstruct.to_string data)) >|= fun crl ->
      Some [ crl ]

  let authenticator ?allowed_hashes ?crl kv =
    let time () = Some (Mirage_ptime.now ()) in
    let now = Mirage_ptime.now () in
    read kv ca_roots_file >|= Cstruct.to_string >>=
    decode_or_fail X509.Certificate.decode_pem_multiple >>= fun cas ->
    let ta = X509.Validation.valid_cas ~time:now cas in
    read_crl kv crl >|= fun crls ->
    X509.Authenticator.chain_of_trust ?crls ?allowed_hashes ~time ta

  let certificate kv =
    let read name =
      read kv (Mirage_kv.Key.v (name ^ ".pem")) >|= Cstruct.to_string >>=
      decode_or_fail X509.Certificate.decode_pem_multiple >>= fun certs ->
      read kv (Mirage_kv.Key.v (name ^ ".key")) >|= Cstruct.to_string >>=
      decode_or_fail X509.Private_key.decode_pem >|= fun pk ->
      (certs, pk)
    in function | `Default   -> read default_cert
                | `Name name -> read name
end
