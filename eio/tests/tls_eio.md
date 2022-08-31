```ocaml
# #require "eio_main";;
# #require "tls-eio";;
```

```ocaml
open Eio.Std

module Flow = Eio.Flow
```

## Mock RNG

It's convenient to use a deterministic RNG when testing, to ensure the tests always give the same result.
Also, it avoids a dependency on mirage-crypto-rng-eio, which isn't released yet.
Obviously, you must not use this in a real application.

```ocaml
(* Override the normal RNG with a mock one for testing.
   This has the same API as the real [Mirage_crypto_rng_eio] so if people copy the
   test cases below then they should work right away. *)
module Mirage_crypto_rng_eio = struct
  module Insecure_test_rng = struct
    type g = int ref

    let block = 1

    let create ?time:_ () = ref 1234

    let generate ~g n =
      let cs = Cstruct.create n in
      for i = 0 to n - 1 do
        Cstruct.set_uint8 cs i !g;
        g := !g + 1
      done;
      cs

    let reseed ~g:_ _ = ()

    let accumulate ~g:_ _ = `Acc ignore

    let seeded ~g:_ = true

    let pools = 0
  end

  let run (module _ : Mirage_crypto_rng.Generator) env fn =
    traceln "Installing non-secure RNG - for testing only!!";
    let insecure_test_rng = Mirage_crypto_rng.create (module Insecure_test_rng) in
    Mirage_crypto_rng.set_default_generator insecure_test_rng;
    fn ()
end

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

let test_client ~net (host, service) =
  match Eio.Net.getaddrinfo_stream net host ~service with
  | [] -> failwith "No addresses found!"
  | addr :: _ ->
    let authenticator = null_auth in
    Switch.run @@ fun sw ->
    let socket = Eio.Net.connect ~sw net addr in
    let flow =
      let host =
        Result.to_option
          (Result.bind (Domain_name.of_string host) Domain_name.host)
      in
      Tls_eio.client_of_flow
        Tls.Config.(client ~version:(`TLS_1_0, `TLS_1_3) ?cached_ticket:!mypsk ~ticket_cache ~authenticator ~ciphers:Ciphers.supported ())
        ?host socket
    in
    let req = String.concat "\r\n" [
      "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
    ] in
    Flow.copy_string req flow;
    let r = Eio.Buf_read.of_flow flow ~max_size:max_int in
    let line = Eio.Buf_read.take 3 r in
    traceln "client <- %s" line;
    traceln "client done."
```

## Test server

```ocaml
let server_config dir =
  let ( / ) = Eio.Path.( / ) in
  let certificate =
    X509_eio.private_of_pems
      ~cert:(dir / "server.pem")
      ~priv_key:(dir / "server.key")
  in
  let ec_certificate =
    X509_eio.private_of_pems
      ~cert:(dir / "server-ec.pem")
      ~priv_key:(dir / "server-ec.key")
  in
  let certificates = `Multiple [ certificate ; ec_certificate ] in
  Tls.Config.(server ~version:(`TLS_1_0, `TLS_1_3) ~certificates ~ciphers:Ciphers.supported ())

let serve_ssl ~config server_s callback =
  Switch.run @@ fun sw ->
  let client, addr = Eio.Net.accept ~sw server_s in
  let flow = Tls_eio.server_of_flow config client in
  traceln "server -> connect";
  callback flow addr
```

## Test case

```ocaml
# Eio_main.run @@ fun env ->
  let net = env#net in
  let certificates_dir = env#cwd in
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  Switch.run @@ fun sw ->
  let addr = `Tcp (Eio.Net.Ipaddr.V4.loopback, 4433) in
  let listening_socket = Eio.Net.listen ~sw net ~backlog:5 ~reuse_addr:true addr in
  (* Eio.Time.with_timeout_exn env#clock 0.1 @@ fun () -> *)
  Fiber.both
    (fun () ->
       traceln "server -> start @@ %a" Eio.Net.Sockaddr.pp addr;
       let config = server_config certificates_dir in
       serve_ssl ~config listening_socket @@ fun flow _addr ->
       traceln "handler accepted";
       let r = Eio.Buf_read.of_flow flow ~max_size:max_int in
       let line = Eio.Buf_read.line r in
       traceln "handler + %s" line;
       Flow.copy_string line flow
    )
    (fun () ->
       test_client ~net ("127.0.0.1", "4433")
    )
  ;;
+Installing non-secure RNG - for testing only!!
+server -> start @ tcp:127.0.0.1:4433
+server -> connect
+handler accepted
+handler + GET / HTTP/1.1
+client <- GET
+client done.
- : unit = ()
```
