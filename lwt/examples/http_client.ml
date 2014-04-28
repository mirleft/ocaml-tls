
open Lwt
open Ex_common

let http_client host port =
  lwt validator = X509_lwt.validator (`Ca_dir ca_cert_dir) in
  lwt sock      = Tls_lwt.connect validator host port
  in
  let req = unlines [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "" ; "" ;
  ] in
  tls_write sock req >> tls_read sock >>= Lwt_io.print

let () =
  match Sys.argv with
  | [| _ ; host ; port |] -> Lwt_main.run (http_client host port)
  | [| _ ; host |]        -> Lwt_main.run (http_client host "443")
  | args                  -> Printf.eprintf "%s <host> <port>\n%!" args.(0)

