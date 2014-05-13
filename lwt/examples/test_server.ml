
open Lwt
open Ex_common

let serve_ssl port callback =

  let tag = "server" in

  lwt cert =
    X509_lwt.private_of_pems
      ~cert:server_cert
      ~priv_key:server_key in

  let server_s =
    let open Lwt_unix in
    let s = socket PF_INET SOCK_STREAM 0 in
    bind s (ADDR_INET (Unix.inet_addr_any, port)) ;
    listen s 10 ;
    s in

  lwt (channels, addr) = Tls_lwt.accept cert server_s in
  yap ~tag "-> connect" >>
  yap ~tag ("-> start @ " ^ string_of_int port) >>
  try_lwt callback channels addr with exn ->
    yap ~tag "+ handler error"


let test_server port =
  let tag = "handler" in
  let rec echo (ic, oc as chans) addr =
    match_lwt Lwt_io.read_line ic with
    | ""   -> yap ~tag "eof."
    | line -> yap ~tag ("+ " ^ line)
              >> Lwt_io.write_line oc line >> echo chans addr
  in
  serve_ssl port echo

let () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  Lwt_main.run (test_server port)
