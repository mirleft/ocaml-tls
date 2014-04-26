
open Lwt

let o f g x = f (g x)

let rec unlines = function
  | []    -> ""
  | [x]   -> x
  | x::xs -> x ^ "\r\n" ^ unlines xs

let cs_of_lines = o Cstruct.of_string unlines

let http_client host port =
  lwt validator = X509_lwt.validator (`Ca_dir "./certificates") in
  lwt sock      = Tls_lwt.connect validator host port in
  let req       = cs_of_lines [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "" ; "" ;
  ] in
  Tls_lwt.write sock req >> Tls_lwt.read sock >>= o Lwt_io.print Cstruct.to_string

let yap ~tag msg = Lwt_io.printf "[%s] %s\n%!" tag msg

let serve_ssl port callback =

  lwt cert =
    X509_lwt.cert_of_pems ~cert:"server.pem" ~priv_key:"server.key" in

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
      try_lwt callback socket addr with
      | exn -> yap ~tag:"server" "+ handler error" in
    loop () in
  yap ~tag:"server" ("-> start @ " ^ string_of_int port) >>
  loop ()


let echo_server port =
  serve_ssl port @@ fun socket addr ->
    yap ~tag:"handler" "-> incoming" >>
    let rec loop () =
      try_lwt
        lwt data = Tls_lwt.read socket in
        yap ~tag:"handler" ("recv: " ^ Cstruct.to_string data) >>
        Tls_lwt.write socket data >>
        loop ()
      with End_of_file -> yap ~tag:"handler" "eof."
    in
    loop ()

let http_client_main () =
  match Sys.argv with
  | [| _ ; host ; port |] -> Lwt_main.run (http_client host port)
  | [| _ ; host |]        -> Lwt_main.run (http_client host "443")
  | args                  -> Printf.eprintf "%s <host> <port>\n%!" args.(0)

let echo_server_main () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  Lwt_main.run (echo_server port)

