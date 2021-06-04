open! Core
open! Async

let server_cert = "./certificates/server.pem"
let server_key = "./certificates/server.key"

module X509_async = struct
  let lift_of_result_msg : ('a, [< `Msg of string ]) result -> 'a Or_error.t =
    Result.map_error ~f:(fun (`Msg message) -> Error.of_string message)
  ;;

  let x509_of_pem pem =
    Cstruct.of_string pem |> X509.Certificate.decode_pem_multiple |> lift_of_result_msg
  ;;

  let certs_of_pems ca_file = Reader.file_contents ca_file >>| x509_of_pem

  let private_of_pems ~cert ~priv_key =
    let open Deferred.Or_error.Let_syntax in
    let%bind certs = certs_of_pems cert in
    let%map priv_key =
      let%bind priv =
        Reader.file_contents priv_key |> Deferred.ok >>| Cstruct.of_string
      in
      X509.Private_key.decode_pem priv |> lift_of_result_msg |> Deferred.return
    in
    certs, priv_key
  ;;
end

let serve_tls port handler =
  let%bind certificate, priv_key =
    X509_async.private_of_pems ~cert:server_cert ~priv_key:server_key
    |> Deferred.Or_error.ok_exn
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
  Tls_async.listen ~on_handler_error config where_to_listen handler
;;

let test_server port =
  let handler (_ : Socket.Address.Inet.t) (_ : Tls_async.Session.t) rd wr =
    let pipe = Reader.pipe rd in
    let rec read_from_pipe () =
      (match%map Pipe.read pipe with
       | `Ok line -> Writer.write wr line
       | `Eof -> ())
      >>= read_from_pipe
    in
    read_from_pipe ()
  in
  serve_tls port handler
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

let () = Command.run cmd
