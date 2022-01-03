type error =
  | Alert of Tls.Packet.alert_type
  | Failure of Tls.Engine.failure
  | Unix_error of Unix.error * string * string
  | Closed

let pp_error ppf = function
  | Alert alert ->
      Fmt.pf ppf "TLS alert: %s" (Tls.Packet.alert_type_to_string alert)
  | Failure failure ->
      Fmt.pf ppf "TLS failure: %s" (Tls.Engine.string_of_failure failure)
  | Unix_error (err, f, arg) ->
      Fmt.pf ppf "%s(%s): %s" f arg (Unix.error_message err)
  | Closed -> Fmt.pf ppf "Connection closed by peer"

(* syscalls *)

let rec fully_write socket str off len =
  if len > 0
  then
    let len' = Unix.write socket (Bytes.unsafe_of_string str) off len in
    fully_write socket str (off + len') (len - len')

let fully_write socket ({ Cstruct.len; _ } as cs) =
  try
    fully_write socket (Cstruct.to_string cs) 0 len ;
    Ok ()
  with Unix.Unix_error (err, f, arg) -> Error (Unix_error (err, f, arg))

let read socket =
  let buf = Bytes.create 0x1000 in
  match Unix.read socket buf 0 (Bytes.length buf) with
  | 0 -> Ok `Eof
  | len -> Ok (`Data (Cstruct.of_bytes ~off:0 ~len buf))
  | exception Unix.Unix_error (err, f, arg) ->
      Error (Unix_error (err, f, arg))

  type flow = {
    role           : [ `Server | `Client ] ;
    flow           : Unix.file_descr ;
    mutable state  : [ `Active of Tls.Engine.state
                     | `Eof
                     | `Error of error ] ;
    mutable linger : Cstruct.t list ;
  }

  let tls_alert a = `Error (Alert a)
  let tls_fail f  = `Error (Failure f)

  let list_of_option = function None -> [] | Some x -> [x]

  let lift_read_result = function
    | Ok (`Data _ | `Eof as x) -> x
    | Error e                  -> `Error e

  let lift_write_result = function
    | Ok ()   -> `Ok ()
    | Error e -> `Error e

  let check_write flow f_res =
    let res = lift_write_result f_res in
    ( match flow.state, res with
      | `Active _, (`Eof | `Error _ as e) ->
          flow.state <- e ; Unix.close flow.flow
      | _ -> ()) ;
    match f_res with
    | Ok ()   -> Ok ()
    | Error e -> Error e

  let read_react flow =

    let handle tls buf =
      match Tls.Engine.handle_tls tls buf with
      | Ok (res, `Response resp, `Data data) ->
          flow.state <- ( match res with
            | `Ok tls      -> `Active tls
            | `Eof         -> `Eof
            | `Alert alert -> tls_alert alert );
          ignore ( match resp with
            | None     -> Ok ()
            | Some buf -> fully_write flow.flow buf |> check_write flow ) ;
          ignore ( match res with
            | `Ok _ -> ()
            | _     -> Unix.close flow.flow ) ;
          `Ok data
      | Error (fail, `Response resp) ->
          let reason = tls_fail fail in
          flow.state <- reason ;
          fully_write flow.flow resp |> fun _ -> Unix.close flow.flow |> fun () -> reason
    in
    match flow.state with
    | `Eof | `Error _ as e -> e
    | `Active _            ->
      read flow.flow |> lift_read_result |>
      function
      | `Eof | `Error _ as e -> flow.state <- e ; e
      | `Data buf            -> match flow.state with
        | `Active tls          -> handle tls buf
        | `Eof | `Error _ as e -> e

  let rec read flow =
    match flow.linger with
    | [] ->
      ( read_react flow |> function
          | `Ok None       -> read flow
          | `Ok (Some buf) -> Ok (`Data buf)
          | `Eof           -> Ok `Eof
          | `Error e       -> Error e )
    | bufs ->
      flow.linger <- [] ;
      Ok (`Data (Cstruct.concat @@ List.rev bufs))

  let writev flow bufs =
    match flow.state with
    | `Eof     -> Error Closed
    | `Error e -> Error e
    | `Active tls ->
        match Tls.Engine.send_application_data tls bufs with
        | Some (tls, answer) ->
            flow.state <- `Active tls ;
            fully_write flow.flow answer |> check_write flow
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
        Ok flow
    | _ ->
      (* read_react re-throws *)
        read_react flow |> function
        | `Ok mbuf ->
            flow.linger <- list_of_option mbuf @ flow.linger ;
            drain_handshake flow
        | `Error e -> Error e
        | `Eof     -> Error Closed

  let reneg ?authenticator ?acceptable_cas ?cert ?(drop = true) flow =
    match flow.state with
    | `Eof        -> Error Closed
    | `Error e    -> Error e
    | `Active tls ->
        match Tls.Engine.reneg ?authenticator ?acceptable_cas ?cert tls with
        | None             ->
            (* XXX make this impossible to reach *)
            invalid_arg "Renegotiation already in progress"
        | Some (tls', buf) ->
            if drop then flow.linger <- [] ;
            flow.state <- `Active tls' ;
            fully_write flow.flow buf |> fun _ ->
            drain_handshake flow |> function
            | Ok _         -> Ok ()
            | Error _ as e -> e

  let key_update ?request flow =
    match flow.state with
    | `Eof        -> Error Closed
    | `Error e    -> Error e
    | `Active tls ->
      match Tls.Engine.key_update ?request tls with
      | Error _ -> invalid_arg "Key update failed"
      | Ok (tls', buf) ->
        flow.state <- `Active tls' ;
        fully_write flow.flow buf |> check_write flow

  let close flow =
    match flow.state with
    | `Active tls ->
      flow.state <- `Eof ;
      let (_, buf) = Tls.Engine.send_close_notify tls in
      fully_write flow.flow buf |> fun _ -> Unix.close flow.flow
    | _           -> ()

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
    fully_write flow init |> fun _ -> drain_handshake tls_flow

  let server_of_flow conf flow =
    let tls_flow = {
      role   = `Server ;
      flow   = flow ;
      state  = `Active (Tls.Engine.server conf) ;
      linger = [] ;
    } in
    drain_handshake tls_flow

