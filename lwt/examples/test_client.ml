
open Lwt
open Ex_common

let test_client _ =
  lwt () = Tls_lwt.rng_init () in
  let port = 4433 in
  let host = "127.0.0.1" in
  lwt authenticator = X509_lwt.authenticator `No_authentication_I'M_STUPID in
  lwt (ic, oc) =
    Tls_lwt.connect_ext
      (Tls.Config.client_exn ~authenticator ~ciphers:Tls.Config.supported_ciphers ())
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
    Lwt_main.run (test_client ())
  with
  | Tls_lwt.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_lwt.Tls_failure alert as exn ->
      print_alert "our end" alert ; raise exn

