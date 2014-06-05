open Lwt

open V1
open V1_LWT


type ('a, 'e, 'c) m = ([< `Ok of 'a | `Error of 'e | `Eof ] as 'c) Lwt.t

let (>>==) (a : ('a, 'e, _) m) (f : 'a -> ('b, 'e, _) m) : ('b, 'e, _) m =
  a >>= function
    | `Ok x                -> f x
    | `Error _ | `Eof as e -> return e


module Color = struct
  open Printf
  let red    fmt = sprintf ("\027[31m"^^fmt^^"\027[m")
  let green  fmt = sprintf ("\027[32m"^^fmt^^"\027[m")
  let yellow fmt = sprintf ("\027[33m"^^fmt^^"\027[m")
  let blue   fmt = sprintf ("\027[36m"^^fmt^^"\027[m")
end


let string_of_err = function
  | `Timeout     -> "TIMEOUT"
  | `Refused     -> "REFUSED"
  | `Unknown msg -> msg

module Log (C: CONSOLE) = struct

  let log_trace c str = C.log_s c (Color.green "+ %s" str)

  and log_data c str buf =
    let repr = String.escaped (Cstruct.to_string buf) in
    C.log_s c (Color.blue "  %s: " str ^ repr)
  and log_error c e = C.log_s c (Color.red "+ err: %s" (string_of_err e))

end

module Server (C  : CONSOLE)
              (S  : STACKV4)
              (KV : KV_RO) =
struct

  module TLS  = Tls_mirage.Make (S.TCPV4)
  module X509 = Tls_mirage.X509 (KV)
  module L    = Log (C)

  let rec handle c tls =
    TLS.read tls >>== fun buf ->
      L.log_data c "recv" buf >> TLS.write tls buf >> handle c tls

  let accept c conf k flow =
    L.log_trace c "accepted." >>
    TLS.server_of_tcp_flow conf flow
    >>== (fun tls -> L.log_trace c "shook hands" >> k c tls)
    >>= function
      | `Ok _    -> assert false
      | `Error e -> L.log_error c e
      | `Eof     -> L.log_trace c "eof."

  let start c stack kv =
    lwt certificate = X509.certificate kv `Default in
    let conf        = Tls.Config.server_exn ~certificate () in
    S.listen_tcpv4 stack 4433 (accept c conf handle) ;
    S.listen stack

end

module Client (C  : CONSOLE)
              (S  : STACKV4)
              (KV : KV_RO) =
struct

  module TLS  = Tls_mirage.Make (S.TCPV4)
  module X509 = Tls_mirage.X509 (KV)
  module L    = Log (C)

  open Ipaddr

  let peer = ((V4.of_string_exn "127.0.0.1", 4433), "localhost")
  let peer = ((V4.of_string_exn "2.19.157.15", 443), "www.apple.com")
  let peer = ((V4.of_string_exn "173.194.70.147", 443), "www.google.com")

  let initial = Cstruct.of_string @@
    "GET / HTTP/1.1\r\nConnection: Close\r\nHost: " ^ snd peer ^ "\r\n\r\n"

  let chat c tls =
    let rec dump () =
      TLS.read tls >>== fun buf ->
        L.log_data c "recv" buf >> dump () in
    TLS.write tls initial >> dump ()

  let start c stack kv =
    lwt validator = X509.validator kv `CAs in
    let conf      = Tls.Config.client_exn ~validator () in
    S.TCPV4.create_connection (S.tcpv4 stack) (fst peer) >>==
    TLS.client_of_tcp_flow conf (snd peer) >>==
    chat c >>= function
    | `Error e -> L.log_error c e
    | `Eof     -> L.log_trace c "eof." 
    | `Ok _    -> assert false

end
