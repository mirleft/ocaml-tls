
open Core.Std
open Async.Std
open Ex_common

let serve_ssl port callback _addr r w =

  let tag = "server" in

  X509_async.private_of_pems
    ~cert:server_cert
    ~priv_key:server_key >>= fun certificate ->
  let config =
    Tls.Config.(server ~certificates:(`Single certificate) ~ciphers:Ciphers.supported ()) in

  yap ~tag ("-> start @ " ^ string_of_int port) ;
  Tls_async.accept_ext config r w >>= fun (r, w) ->
  yap ~tag "-> connect" ;
  callback r w >>| fun () ->
  yap ~tag "<- handler done"


let test_server port =
  let cb r w =
    Reader.read_line r >>= function
    | `Eof -> raise End_of_file
    | `Ok line ->
      yap ~tag:"handler" ("+ " ^ line) ;
      Writer.write_line w line ;
      Writer.flushed w
  in
  Tcp.(Server.create (on_port port) (serve_ssl port cb)) >>= fun _srv ->
  Deferred.unit

let () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  don't_wait_for @@ (test_server port) ;
  never_returns @@ Scheduler.go ()
