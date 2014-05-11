
open Lwt

let o f g x = f (g x)

let rec unlines = function
  | []    -> ""
  | [x]   -> x
  | x::xs -> x ^ "\r\n" ^ unlines xs

let tls_read s  = Tls_lwt.read s >|= Cstruct.to_string
let tls_write s = o (Tls_lwt.write s) Cstruct.of_string

let ca_cert_dir = "./certificates"
let server_cert = "./certificates/server.pem"
let server_key  = "./certificates/server.key"

let yap ~tag msg = Lwt_io.printf "[%s] %s\n%!" tag msg
