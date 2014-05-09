open Lwt
open V1_LWT

module Color = struct
  open Printf
  let red    fmt = sprintf ("\027[31m"^^fmt^^"\027[m")
  let green  fmt = sprintf ("\027[32m"^^fmt^^"\027[m")
  let yellow fmt = sprintf ("\027[33m"^^fmt^^"\027[m")
  let blue   fmt = sprintf ("\027[36m"^^fmt^^"\027[m")
end

let o f g x = f (g x)

module Server (C: CONSOLE) (S: STACKV4) (Kv: KV_RO) = struct

  module TCP = S.TCPV4
  module TLS = Tls_mirage.Make (TCP)

  module Cs = Tls.Utils.Cs

  let lower exn_of_err f =
    f >>= function | `Ok r    -> return r
                   | `Error e -> fail (exn_of_err e)

  let lower_kv f =
    let aux (Kv.Unknown_key key) = Invalid_argument ("Kv: " ^ key) in
    lower aux f


  let string_of_err = function
    | `Timeout     -> "TIMEOUT"
    | `Refused     -> "REFUSED"
    | `Unknown msg -> msg

  let rec handle c tls =
    TLS.read tls >>= function
    | `Eof     -> C.log_s c Color.(green "+ eof.")
    | `Error e -> C.log_s c Color.(red "+ error: %s" (string_of_err e))
    | `Ok buf  ->
        let repr = String.escaped (Cstruct.to_string buf) in
        C.log_s c Color.(blue "  recv: %s" repr) >>
        TLS.write tls buf >> handle c tls

  let kv_read_full kv ~name =
    lower_kv (Kv.size kv name) >|= Int64.to_int >>=
    o lower_kv (Kv.read kv name 0) >|= Cs.appends

  let load_secrets kv =
    let open Tls.X509 in
    lwt cert = kv_read_full kv "server.pem" >|= Cert.of_pem_cstruct1
    and key  = kv_read_full kv "server.key" >|= PK.of_pem_cstruct1 in
    return (cert, key)

  let accept c cert k flow =
    C.log_s c Color.(green "+ accepted.") >>
    TLS.server_of_tcp_flow cert flow >>= function
      | `Ok tls  -> C.log_s c Color.(green "+ shook hands") >> k c tls
      | `Error e -> C.log_s c Color.(red "+ handhake: %s" (string_of_err e))

  let start c stack kv =
    lwt cert = load_secrets kv in
    S.listen_tcpv4 stack 4433 (accept c cert handle) ;
    S.listen stack

end
