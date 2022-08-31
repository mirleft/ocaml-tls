```ocaml
# #require "eio_main";;
# #require "lwt_eio";;
# #require "tls-eio";;
```

```ocaml
open Lwt.Infix
open Eio.Std
```

## Test client

```ocaml
let null_auth ?ip:_ ~host:_ _ = Ok None

let mypsk = ref None

let ticket_cache = {
  Tls.Config.lookup = (fun _ -> None) ;
  ticket_granted = (fun psk epoch ->
      Logs.info (fun m -> m "ticket granted %a %a"
                    Sexplib.Sexp.pp_hum (Tls.Core.sexp_of_psk13 psk)
                    Sexplib.Sexp.pp_hum (Tls.Core.sexp_of_epoch_data epoch)) ;
      mypsk := Some (psk, epoch)) ;
  lifetime = 0l ;
  timestamp = Ptime_clock.now
}

let test_client () =
  let port = 4433 in
  let host = "127.0.0.1" in
  let authenticator = null_auth in
  let ic, oc = Lwt_eio.run_lwt @@ fun () ->
    Tls_eio.connect_ext
      Tls.Config.(client ~version:(`TLS_1_0, `TLS_1_3) ?cached_ticket:!mypsk ~ticket_cache ~authenticator ~ciphers:Ciphers.supported ())
      (host, port)
  in
  let req = String.concat "\r\n" [
    "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
  ] in
  Lwt_eio.run_lwt (fun () -> Lwt_io.(write oc req));
  let line = Lwt_eio.run_lwt (fun () -> Lwt_io.read ~count:3 ic) in
  traceln "client <- %s" line;
  Lwt_eio.run_lwt (fun () -> Lwt_io.close oc);
  traceln "client done."
```

## Test server

```ocaml
let server_cert = "server.pem"
let server_key  = "server.key"
let server_ec_cert = "server-ec.pem"
let server_ec_key  = "server-ec.key"

let serve_ssl port callback =
  Lwt_eio.run_lwt @@ fun () ->

  X509_eio.private_of_pems
    ~cert:server_cert
    ~priv_key:server_key >>= fun certificate ->
  X509_eio.private_of_pems
    ~cert:server_ec_cert
    ~priv_key:server_ec_key >>= fun ec_certificate ->
  let certificates = `Multiple [ certificate ; ec_certificate ] in
  let config =
    Tls.Config.(server ~version:(`TLS_1_0, `TLS_1_3) ~certificates ~ciphers:Ciphers.supported ()) in

  let server_s =
    let open Lwt_unix in
    let s = socket PF_INET SOCK_STREAM 0 in
    setsockopt s Unix.SO_REUSEADDR true ;
    bind s (ADDR_INET (Unix.inet_addr_any, port)) >|= fun () ->
    listen s 10 ;
    s in

  traceln "server -> start @@ %d" port;
  server_s >>= fun s ->
  Tls_eio.accept_ext config s >>= fun (channels, addr) ->
  traceln "server -> connect";
  callback channels addr >>= fun () ->
  traceln "server <- handler done";
  Lwt.return_unit
```

```ocaml
# Eio_main.run @@ fun env ->
  Lwt_eio.with_event_loop ~clock:env#clock @@ fun () ->
  Fiber.both
    (fun () ->
       serve_ssl 4433 @@ fun (ic, oc) _addr ->
       traceln "handler accepted";
       Lwt_io.read_line ic >>= fun line ->
       traceln "handler + %s" line;
       Lwt_io.write_line oc line
    )
    (fun () ->
       Eio_unix.sleep 0.1;
       test_client ()
    )
  ;;
+server -> start @ 4433
+server -> connect
+handler accepted
+handler + GET / HTTP/1.1
+server <- handler done
+client <- GET
+client done.
- : unit = ()
```
