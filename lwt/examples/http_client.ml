
open Lwt
open Ex_common

let http_client ?ca host port =
  lwt validator = X509_lwt.validator
    (match ca with
     | None        -> `Ca_dir ca_cert_dir
     | Some "NONE" -> `No_validation_I'M_STUPID
     | Some f      -> `Ca_file f)
  in
  lwt sock      = Tls_lwt.connect validator host port
  in
  let req = unlines [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "" ; "" ;
  ] in
  tls_write sock req >> tls_read sock >>= Lwt_io.print

let () =
  match Sys.argv with
  | [| _ ; host ; port ; trust |] -> Lwt_main.run (http_client host port ~ca:trust)
  | [| _ ; host ; port |]         -> Lwt_main.run (http_client host port)
  | [| _ ; host |]                -> Lwt_main.run (http_client host "443")
  | args                          -> Printf.eprintf "%s <host> <port>\n%!" args.(0)

