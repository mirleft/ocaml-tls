open Lwt
open V1_LWT


module Color = struct
  open Printf
  let red    fmt = sprintf ("\027[31m"^^fmt^^"\027[m")
  let green  fmt = sprintf ("\027[32m"^^fmt^^"\027[m")
  let yellow fmt = sprintf ("\027[33m"^^fmt^^"\027[m")
  let blue   fmt = sprintf ("\027[36m"^^fmt^^"\027[m")
end

module Cs  = Tls.Utils.Cs

let o f g x = f (g x)

let lower exn_of_err f =
  f >>= function | `Ok r    -> return r
                 | `Error e -> fail (exn_of_err e)

let string_of_err = function
  | `Timeout     -> "TIMEOUT"
  | `Refused     -> "REFUSED"
  | `Unknown msg -> msg


module Kv_util (Kv: KV_RO) = struct

  let lower_kv f =
    let aux (Kv.Unknown_key key) = Invalid_argument ("Kv: " ^ key) in
    lower aux f

  let read_full kv ~name =
    lower_kv (Kv.size kv name) >|= Int64.to_int >>=
    o lower_kv (Kv.read kv name 0) >|= Cs.appends
end

module Log (C: CONSOLE) = struct

  let log_trace c str = C.log_s c (Color.green "+ %s" str)

  and log_data c str buf =
    let repr = String.escaped (Cstruct.to_string buf) in
    C.log_s c (Color.blue "  %s: " str ^ repr)
  and log_error c e = C.log_s c (Color.red "+ err: %s" (string_of_err e))

end

module Server (C: CONSOLE) (S: STACKV4) (Kv: KV_RO) = struct

  module TLS = Tls_mirage.Make (S.TCPV4)
  module Kvu = Kv_util (Kv)
  module L   = Log (C)

  let rec handle c tls =
    TLS.read tls >>= function
    | `Eof     -> L.log_trace c "eof."
    | `Error e -> L.log_error c e
    | `Ok buf  -> L.log_data c "recv" buf >> TLS.write tls buf >> handle c tls

  let load_secrets kv =
    let open Tls.X509 in
    lwt cert = Kvu.read_full kv "server.pem" >|= Cert.of_pem_cstruct1
    and key  = Kvu.read_full kv "server.key" >|= PK.of_pem_cstruct1 in
    return (cert, key)

  let accept c cert k flow =
    L.log_trace c "accepted." >>
    TLS.server_of_tcp_flow cert flow >>= function
      | `Ok tls  -> L.log_trace c "shook hands" >> k c tls
      | `Error e -> L.log_error c e

  let start c stack kv =
    lwt cert = load_secrets kv in
    S.listen_tcpv4 stack 4433 (accept c cert handle) ;
    S.listen stack

end
