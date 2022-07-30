open! Core
open! Async

let server_cert = "./certificates/server.pem"
let server_key = "./certificates/server.key"

let serve_tls port handle_client =
  let%bind certificate =
    Tls_async.X509_async.Certificate.of_pem_file server_cert |> Deferred.Or_error.ok_exn
  in
  let%bind priv_key =
    Tls_async.X509_async.Private_key.of_pem_file server_key |> Deferred.Or_error.ok_exn
  in
  let config =
    Tls.Config.(
      server
        ~version:(`TLS_1_0, `TLS_1_2)
        ~certificates:(`Single (certificate, priv_key))
        ~ciphers:Ciphers.supported
        ())
  in
  let where_to_listen = Tcp.Where_to_listen.of_port port in
  let on_handler_error = `Ignore in
 Tcp.Server.create
     ~on_handler_error
     where_to_listen
    (fun sa r w ->
      printf !"connection establised from %{Socket.Address.Inet} starting TLS\n" sa;
      Tls_async.tls_handler ~config ~handle_client sa r w)
;;

let test_server port =
  let handler_client (_ : Socket.Address.Inet.t) (_ : Tls_async.Session.t) rd wr =
    let pipe = Reader.pipe rd in
    let rec read_from_pipe () =
      (match%map Pipe.read pipe with
       | `Ok line -> Writer.write wr line
       | `Eof -> ())
      >>= read_from_pipe
    in
    read_from_pipe ()
  in
  serve_tls port handler_client
;;

let cmd =
  let open Command.Let_syntax in
  Command.async
    ~summary:"test server"
    (let%map_open port = anon ("PORT" %: int) in
     fun () ->
       let open Deferred.Let_syntax in
       let%bind server = test_server port in
       Tcp.Server.close_finished server)
;;

let () = Command_unix.run cmd
