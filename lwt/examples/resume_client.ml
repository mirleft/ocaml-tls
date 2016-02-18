
open Lwt
open Ex_common

let http_client ?ca ?fp host port =
  let port          = int_of_string port in
  X509_lwt.authenticator
    ( match ca, fp with
      | None, Some fp  -> `Hex_key_fingerprints (`SHA256, [(host, fp)])
      | None, _        -> `Ca_dir ca_cert_dir
      | Some "NONE", _ -> `No_authentication_I'M_STUPID
      | Some f, _      -> `Ca_file f ) >>= fun authenticator ->
  let config = Tls.Config.client ~authenticator () in
  Tls_lwt.Unix.connect ~trace:eprint_sexp config (host, port) >>= fun t ->
  Tls_lwt.Unix.write t (Cstruct.of_string "foo\n") >>= fun () ->
  let cs = Cstruct.create 4 in
  Tls_lwt.Unix.read t cs >>= fun _len ->
  let cached_session = match Tls_lwt.Unix.epoch t with
    | `Ok e -> e
    | `Error -> invalid_arg "error retrieving epoch"
  in
  Printf.printf "cached session: %s\n" (Sexplib.Sexp.to_string_hum (Tls.Core.sexp_of_epoch_data cached_session)) ;
  Tls_lwt.Unix.close t >>= fun () ->
  Printf.printf "closed session\n" ;
  let config = Tls.Config.client ~authenticator ~cached_session () in
  Tls_lwt.connect_ext ~trace:eprint_sexp config (host, port) >>= fun (ic, oc) ->
  let req = String.concat "\r\n" [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
  ] in
  Lwt_io.(write oc req >>= fun () -> read ic >>= print >>= fun () -> printf "++ done.\n%!")

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

