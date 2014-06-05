
open Lwt
open Ex_common

let http_client ?ca host port =
  lwt () = Tls_lwt.rng_init () in
  let port      = int_of_string port in
  lwt validator = X509_lwt.validator
    ( match ca with
      | None        -> `Ca_dir ca_cert_dir
      | Some "NONE" -> `No_validation_I'M_STUPID
      | Some f      -> `Ca_file f )
  in
  lwt (ic, oc) =
    Tls_lwt.connect_ext
      (Tls.Config.client_exn ~validator ~require_secure_rekeying:false ())
      (host, port) in
  let req = String.concat "\r\n" [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
  ] in
  Lwt_io.(write oc req >> read ic >>= print >> printf "++ done.\n%!")

let print_alert where alert =
    Printf.eprintf "TLS ALERT (%s): %s\n%!"
      where (Tls.Packet.alert_type_to_string alert)

let () =
  try
    match Sys.argv with
    | [| _ ; host ; port ; trust |] -> Lwt_main.run (http_client host port ~ca:trust)
    | [| _ ; host ; port |]         -> Lwt_main.run (http_client host port)
    | [| _ ; host |]                -> Lwt_main.run (http_client host "443")
    | args                          -> Printf.eprintf "%s <host> <port>\n%!" args.(0)
  with
  | Tls_lwt.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_lwt.Tls_failure alert as exn ->
      print_alert "our end" alert ; raise exn

