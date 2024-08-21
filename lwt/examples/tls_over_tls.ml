open Lwt
open Ex_common

let hostname = "mirage.io"

let proxy = "127.0.0.1", 3129

(* To test TLS-over-TLS, the `squid` proxy can be installed locally and configured to support HTTPS:

- Generate a certificate for localhost: https://gist.github.com/cecilemuller/9492b848eb8fe46d462abeb26656c4f8

$ openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout RootCA.key -out RootCA.pem -subj "/C=US/CN=Example-Root-CA"
$ openssl x509 -outform pem -in RootCA.pem -out RootCA.crt
$ cat <<EOF > domains.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
EOF
$ openssl req -new -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.csr -subj "/C=US/ST=YourState/L=YourCity/O=Example-Certificates/CN=localhost.local"
$ openssl x509 -req -sha256 -days 1024 -in localhost.csr -CA RootCA.pem -CAkey RootCA.key -CAcreateserial -extfile domains.ext -out localhost.crt

- Configure squid by adding HTTPS support on port 3129 in /etc/squid/squid.conf :

https_port 3129 tls-cert=/path/to/localhost.crt tls-key=/path/to/localhost.key

*)

let client = get_ok (Tls.Config.client ~authenticator:null_auth ())

let string_prefix ~prefix msg =
  let len = String.length prefix in
  String.length msg >= len && String.sub msg 0 len = prefix

let host = Result.get_ok (Domain_name.of_string hostname)
let host = Result.get_ok (Domain_name.host host)

let test_client _ =
  (* Connect to proxy *)
  Tls_lwt.Unix.connect client proxy >>= fun t ->
  let (ic, oc) = Tls_lwt.of_t t in

  (* Request proxy to connect to hostname *)
  let req =
    Printf.sprintf "CONNECT %s:443 HTTP/1.1\r\nHost: %s\r\n\r\n"
      hostname hostname
  in
  Lwt_io.write oc req >>= fun () ->
  Lwt_io.read ic ~count:1024 >>= fun msg ->
  assert (string_prefix ~prefix:"HTTP/1.1 200 " msg) ;

  (* TLS with hostname, over the TLS connection with the proxy *)
  Tls_lwt.Unix.client_of_channels client ~host (ic, oc) >>= fun t ->
  let (ic, oc) = Tls_lwt.of_t t in

  (* Request homepage from host *)
  let req =
    Printf.sprintf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
      hostname
  in

  Lwt_io.(write oc req >>= fun () ->
          read ~count:1024 ic >>= print >>= fun () ->
          read ~count:1024 ic >>= print >>= fun () ->
          close oc >>= fun () ->
          printf "++ done.\n%!")

let () = Lwt_main.run (test_client ())
