
open Lwt

let o f g x = f (g x)

let ca_cert_dir = "./certificates"
let server_cert = "./certificates/server.pem"
let server_key  = "./certificates/server.key"

let yap ~tag msg = Lwt_io.printf "[%s] %s\n%!" tag msg

let lines ic =
  Lwt_stream.from @@ fun () ->
    Lwt_io.read_line_opt ic >>= function
      | None -> Lwt_io.close ic >> return_none
      | line -> return line

let eprint_sexp sexp =
  output_string stderr Sexplib.Sexp.(to_string_hum sexp) ;
  output_string stderr "\n\n" ;
  flush stderr
