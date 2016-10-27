open Mirage

let secrets_dir = "sekrit"

let disk  = direct_kv_ro secrets_dir
and stack = socket_stackv4 [Ipaddr.V4.any]

let packages = [ "mirage-clock-unix" ; "mirage-http" ; "tcpip" ; "channel" ]
and libraries = [ "mirage-clock-unix" ; "tls"; "tls.mirage" ; "tcpip"; "channel" ; "cohttp.lwt-core" ; "mirage-http" ]

let server = foreign ~deps:[abstract nocrypto] ~libraries ~packages "Unikernel.Main" @@ stackv4 @-> kv_ro @-> pclock @-> job

let () =
  register "tls-server" [ server $ stack $ disk $ default_posix_clock ]
