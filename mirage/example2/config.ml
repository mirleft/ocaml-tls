open Mirage

let secrets_dir = "sekrit"

let disk  = direct_kv_ro secrets_dir
and stack = socket_stackv4 default_console [Ipaddr.V4.any]

let server = foreign "Unikernel.Main" @@ console @-> stackv4 @-> kv_ro @-> job

let () =
  add_to_ocamlfind_libraries [
    "tls"; "tls.mirage";
    "tcpip.channel";
    "cohttp.lwt-core"; "mirage-http"
  ] ;
  register "tls-server" [ server $ default_console $ stack $ disk ]
