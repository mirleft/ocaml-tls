
open Lwt

let o f g x = f (g x)

let ca_cert_dir = "./certificates"
let server_cert = "./certificates/server.pem"
let server_key  = "./certificates/server.key"

let yap ~tag msg = Lwt_io.printf "[%s] %s\n%!" tag msg

let lines ic =
  Lwt_stream.from @@ fun () ->
    Lwt_io.read_line ic >>= function
      | "" -> Lwt_io.close ic >> return_none
      | ln -> return (Some ln)

