
open Core.Std
open Async.Std
open Ex_common

let test_client _ =
  let buf = String.create 4096 in
  let host = "localhost" in
  let port = 4433 in
  Tcp.(connect (to_host_and_port host port)) >>= fun (_sock, r, w) ->
  X509_async.authenticator `No_authentication_I'M_STUPID >>= fun authenticator ->
  Tls_async.connect_ext
    Tls.Config.(client ~authenticator ~ciphers:Ciphers.supported ())
    ~host r w >>= fun (r, w) ->
  let req = String.concat ~sep:"\r\n" [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
  ] in
  Writer.write w req ;
  Writer.flushed w >>= fun () ->
  Reader.read r buf >>| function
  | `Eof -> raise End_of_file
  | `Ok n ->
    let msg = String.subo buf ~len:n in
    printf "%s" msg

let main () =
  try test_client ()
  with
  | Tls_async.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_async.Tls_failure alert as exn ->
      print_fail "our end" alert ; raise exn

let () =
  don't_wait_for @@ main () ;
  never_returns @@ Scheduler.go ()
