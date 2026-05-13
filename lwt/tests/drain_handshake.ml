open Lwt.Infix

let client_cfg =
  let null_auth ?ip:_ ~host:_ _ = Ok None in
  Result.get_ok (Tls.Config.client ~authenticator:null_auth ())

let assert_read_returns_0 flow =
  let buf = Bytes.create 1 in
  Tls_lwt.Unix.read flow buf >|= fun n -> assert (n = 0)

let assert_end_of_file f =
  Lwt.catch
    (fun () -> f () >|= fun _ -> assert false)
    (function End_of_file -> Lwt.return_unit | exn -> Lwt.reraise exn)

let pipes () =
  let client_in, server_out = Lwt_io.pipe () in
  let server_in, client_out = Lwt_io.pipe () in
  client_in, client_out, server_in, server_out

let completed_read_closed_reports_eof server_cfg timing =
  let client_in, client_out, server_in, server_out = pipes () in
  let client =
    Tls_lwt.Unix.client_of_channels client_cfg (client_in, client_out)
  in
  let server =
    Tls_lwt.Unix.server_of_channels server_cfg (server_in, server_out)
  in
  client >>= fun client ->
  (match timing with
   | `Coalesced ->
       Tls_lwt.Unix.close client >>= fun () ->
       server
   | `Split ->
       Lwt_io.flush client_out >>= fun () ->
       server >>= fun server ->
       Tls_lwt.Unix.close client >|= fun () ->
       server)
  >>= fun server ->
  assert_read_returns_0 server

let closed_before_handshake_fails server_cfg =
  let server_in, client_out = Lwt_io.pipe () in
  Lwt_io.close client_out >>= fun () ->
  assert_end_of_file (fun () ->
      Tls_lwt.Unix.server_of_channels server_cfg (server_in, Lwt_io.null))

let () =
  Mirage_crypto_rng_unix.use_default ();
  Lwt_main.run
    (X509_lwt.private_of_pems ~cert:"server.pem" ~priv_key:"server.key"
     >>= fun certificate ->
     let server_cfg =
       Result.get_ok Tls.Config.(server ~certificates:(`Single certificate) ())
     in
     closed_before_handshake_fails server_cfg >>= fun () ->
     completed_read_closed_reports_eof server_cfg `Split >>= fun () ->
     completed_read_closed_reports_eof server_cfg `Coalesced)
