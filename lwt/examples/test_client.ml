
open Lwt
open Ex_common

let cached_session =
  let hex = Nocrypto.Uncommon.Cs.of_hex in
  {
    Tls.Core.protocol_version = Tls.Core.TLS_1_3 ;
    ciphersuite = `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 ;
    peer_random = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
    peer_certificate = None ;
    peer_certificate_chain = [] ;
    peer_name = None ;
    trust_anchor = None ;
    received_certificates = [] ;
    own_random = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
    own_certificate = [] ;
    own_private_key = None ;
    own_name = None ;
    master_secret = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
    session_id = Cstruct.create 0 ;
    extended_ms = true ;
    resumption_secret = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
    psk_id = hex "0000"
  }

let test_client _ =
  let port = 4433 in
  let host = "127.0.0.1" in
  X509_lwt.authenticator `No_authentication_I'M_STUPID >>= fun authenticator ->
  Tls_lwt.connect_ext
    Tls.Config.(client ~authenticator ~cached_session ~ciphers:Ciphers.supported ())
    (host, port) >>= fun (ic, oc) ->
  let req = String.concat "\r\n" [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
  ] in
  Lwt_io.(write oc req >>= fun () -> read ic >>= print >>= fun () -> printf "++ done.\n%!")

let () =
  try
    Lwt_main.run (test_client ())
  with
  | Tls_lwt.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_lwt.Tls_failure alert as exn ->
      print_fail "our end" alert ; raise exn

