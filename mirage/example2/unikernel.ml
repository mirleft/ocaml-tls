
open Lwt
open V1_LWT

module Main (C  : CONSOLE)
            (S  : STACKV4)
            (KV : KV_RO) =
struct

  module TLS  = Tls_mirage.Make_flow (S.TCPV4)
  module X509 = Tls_mirage.X509 (KV)
  module Chan = Channel.Make (TLS)
  module Http = HTTP.Make (Chan)

  open Http
  module Body = Cohttp_lwt_body

  let handle c conn req body =
    let resp = Http.Response.make ~status:`OK () in
    lwt body =
      lwt inlet = match req.Http.Request.meth with
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
