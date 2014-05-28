
open Lwt
open V1_LWT

type ('a, 'e, 'c) m = ([< `Ok of 'a | `Error of 'e | `Eof ] as 'c) Lwt.t

let (>>==) (a : ('a, 'e, _) m) (f : 'a -> ('b, 'e, _) m) : ('b, 'e, _) m =
  a >>= function
    | `Ok x                -> f x
    | `Error _ | `Eof as e -> return e

let o f g x = f (g x)

module Main (C  : CONSOLE)
            (S  : STACKV4)
            (KV : KV_RO) =
struct

  module TLS  = Tls_mirage.Make_flow (S.TCPV4)
  module X509 = Tls_mirage.X509 (KV)
  module Chan = Channel.Make (TLS)
  module Http = HTTP.Make (Chan)

  let handle c conn req body = fail (Failure "No-one's home.")

  let upgrade c tls_param tcp =
    TLS.server_of_tcp_flow tls_param tcp >>= function
      | `Error _ -> fail (Failure "tls init")
      | `Ok tls  ->
          let open Http.Server in
          listen { callback = handle c ; conn_closed = fun _ () -> () } tls

  let start c stack kv =
    lwt cert = X509.certificate kv `Default in
    S.listen_tcpv4 stack 4433 (upgrade c cert) ;
    S.listen stack

end
