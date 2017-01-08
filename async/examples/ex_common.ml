open Async.Std
open Log.Global

let ca_cert_dir = "./certificates"
let server_cert = "./certificates/server.pem"
let server_key  = "./certificates/server.key"

let yap ~tag msg = printf "[%s] %s\n%!" tag msg

(* let lines ic = *)
(*   Lwt_stream.from @@ fun () -> *)
(*     Lwt_io.read_line_opt ic >>= function *)
(*       | None -> Lwt_io.close ic >>= fun () -> return_none *)
(*       | line -> return line *)

let eprint_sexp sexp =
  printf "%s" Sexplib.Sexp.(to_string_hum sexp)

let print_alert where alert =
  printf "TLS ALERT (%s): %s\n%!"
    where (Tls.Packet.alert_type_to_string alert)

let print_fail where fail =
  printf "TLS FAIL (%s): %s\n%!"
    where (Tls.Engine.string_of_failure fail)
