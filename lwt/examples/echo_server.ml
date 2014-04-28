
open Lwt
open Ex_common

let serve_ssl port callback =

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

  let rec loop () =
    lwt (socket, addr) = Tls_lwt.accept ~cert server_s in
    yap ~tag:"server" "-> connect" >>
    let _ =
      try_lwt callback socket addr
      with exn -> yap ~tag:"server" "+ handler error" in
    loop () in
  yap ~tag:"server" ("-> start @ " ^ string_of_int port) >>
  loop ()


let echo_server port =
  serve_ssl port @@ fun socket addr ->
    yap ~tag:"handler" "-> incoming" >>
    let rec loop () =
      try_lwt
        lwt data = tls_read socket in
        yap ~tag:"handler" ("recv: " ^ data) >> tls_write socket data >> loop ()
      with End_of_file -> yap ~tag:"handler" "eof."
    in
    loop ()

let () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  Lwt_main.run (echo_server port)
