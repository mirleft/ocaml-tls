
open Lwt
open V1_LWT

module Main (C  : CONSOLE)
            (S  : STACKV4)
            (KV : KV_RO) =
struct

  module TLS  = Tls_mirage.Make (S.TCPV4)
  module X509 = Tls_mirage.X509 (KV) (Clock)
  module Http = Cohttp_mirage.Server (TLS)

  module Body = Cohttp_lwt_body

  let handle c conn req body =
    let resp = Http.Response.make ~status:`OK () in
    lwt body =
      lwt inlet = match Http.Request.meth req with
        | `POST ->
            lwt contents = Body.to_string body in
            return @@ "<pre>" ^ contents ^ "</pre>"
        | _     -> return "" in
      return @@ Body.of_string @@
        "<html><head><title>ohai</title></head>
         <body><h3>Secure CoHTTP on-line.</h3>"
         ^ inlet ^ "</body></html>\r\n"
    in
    return (resp, body)

  let upgrade c conf tcp =
    TLS.server_of_flow conf tcp >>= function
      | `Error _  | `Eof -> fail (Failure "tls init")
      | `Ok tls  ->
        let t = Http.make (handle c) () in
        Http.listen t tls

  let start c stack kv =
    lwt cert = X509.certificate kv `Default in
    let conf = Tls.Config.server ~certificates:(`Single cert) () in
    S.listen_tcpv4 stack 4433 (upgrade c conf) ;
    S.listen stack

end
