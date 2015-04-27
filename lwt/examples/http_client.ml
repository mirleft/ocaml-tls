
open Lwt
open Ex_common

let http_client ?ca ?fp host port =
  Nocrypto_entropy_lwt.initialize () >>
  let port          = int_of_string port in
  lwt authenticator = X509_lwt.authenticator
    ( match ca, fp with
      | None, Some fp  -> `Hex_fingerprints (`SHA256, [(host, fp)])
      | None, _        -> `Ca_dir ca_cert_dir
      | Some "NONE", _ -> `No_authentication_I'M_STUPID
      | Some f, _      -> `Ca_file f )
  in
  lwt (ic, oc) =
    Tls_lwt.connect_ext
      ~trace:eprint_sexp
      (Tls.Config.client ~authenticator ())
      (host, port) in
  let req = String.concat "\r\n" [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
  ] in
  Lwt_io.(write oc req >> read ic >>= print >> printf "++ done.\n%!")

let () =
  try
    match Sys.argv with
    | [| _ ; host ; port ; "FP" ; fp |] -> Lwt_main.run (http_client host port ~fp)
    | [| _ ; host ; port ; trust |] -> Lwt_main.run (http_client host port ~ca:trust)
    | [| _ ; host ; port |]         -> Lwt_main.run (http_client host port)
    | [| _ ; host |]                -> Lwt_main.run (http_client host "443")
    | args                          -> Printf.eprintf "%s <host> <port>\n%!" args.(0)
  with
  | Tls_lwt.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_lwt.Tls_failure fail as exn ->
      print_fail "our end" fail ; raise exn

