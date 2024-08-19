
module Flow = struct

  let rewrap_st = function (`S _, st) -> `S st | (`C _, st) -> `C st

  let unwrap_st = function `S st -> st | `C st -> st

  let can_handle_appdata st =
    not (Tls.Engine.handshake_in_progress (unwrap_st st))

  let send_application_data state data =
    match Tls.Engine.send_application_data (unwrap_st state) data with
    | None           -> None
    | Some (st', cs) -> Some (rewrap_st (state, st'), cs)

  let handle_tls ~tag state msg =
    let (st, descr) = match state with
      | `S st -> (st, "server")
      | `C st -> (st, "client")
    in
    match msg with
    | None -> state, None, None
    | Some msg ->
    match Tls.Engine.handle_tls st msg with
    | Ok (_, Some `Eof, _, _) ->
        failwith "received eof"
    | Ok (st', _eof, `Response (Some ans), `Data appdata) ->
        (rewrap_st (state, st'), Some ans, appdata)
    | Ok (st', _eof, `Response None, `Data appdata) ->
        (rewrap_st (state, st'), None, appdata)
    | Error (a, _) ->
        failwith @@ Printf.sprintf "[%s] %s error: %s"
          tag descr (Tls.Engine.string_of_failure a)
end

let loop_chatter ~certificate ~loops ~size =

  Printf.eprintf "Looping %d times, %d bytes.\n%!" loops size;

  let message  = Mirage_crypto_rng.generate size
  and server   = Tls.(Engine.server (Config.server ~certificates:(`Single certificate) ()))
  and (client, init) =
    let authenticator ?ip:_ ~host:_ _ = Ok None in
    Tls.(Engine.client @@ Config.client ~authenticator ())
  in
  Testlib.time @@ fun () ->

    let rec handshake srv cli cli_msg =
      let tag = "handshake" in
      let (srv, ans, _) = Flow.handle_tls ~tag srv cli_msg in
      let (cli, ans, _) = Flow.handle_tls ~tag cli ans in
      if Flow.can_handle_appdata cli && Flow.can_handle_appdata srv then (srv, cli) else
          handshake srv cli ans

    and chat srv cli data = function
      | 0 -> data
      | n ->
          let tag = "chat" in
          let simplex sender recv data =
            match Flow.send_application_data sender [data] with
            | None                -> failwith @@ "can't send"
            | Some (sender', msg) ->
                match Flow.handle_tls ~tag recv (Some msg) with
                | (recv', _, Some data') -> (sender', recv', data')
                | (_, _, None)           -> failwith "expected data"
          in
          let (cli, srv, data1) = simplex cli srv data in
          let (srv, cli, data2) = simplex srv cli data1 in
          chat srv cli data2 (pred n)
    in
    let (srv, cli) = handshake (`S server) (`C client) (Some init) in
    let message' = chat srv cli message loops in
    if Cstruct.equal message message' then Ok ()
    else Error "the message got corrupted :("


let load_priv () =
  let cert, key =
    if Sys.file_exists "./certificates/server.pem" then
      "./certificates/server.pem", "./certificates/server.key"
    else
      "server.pem", "server.key"
  in
  let cs1 = Testlib.cs_mmap cert
  and cs2 = Testlib.cs_mmap key in
  match
    X509.Certificate.decode_pem_multiple cs1, X509.Private_key.decode_pem cs2
  with
  | Ok certs, Ok key -> certs, key
  | Error (`Msg m), _ -> failwith ("can't parse certificates " ^ m)
  | _, Error (`Msg m) -> failwith ("can't parse private key " ^ m)

let jump () loops size =
  let certificate = load_priv () in
  loop_chatter ~certificate ~loops ~size

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let loops =
  let doc = "Number of loops to take" in
  Arg.(value & opt int 10 & info ~docv:"LOOPS" ~doc ["loops"])

let size =
  let doc = "Bytes to exchange" in
  Arg.(value & opt int 1024 & info ~docv:"SIZE" ~doc ["size"])

let cmd =
  let term = Term.(const jump $ setup_log $ loops $ size)
  and info = Cmd.info "feedback" ~version:"%%VERSION_NUM%%"
  in
  Cmd.v info term

let () = exit (Cmd.eval_result cmd)
