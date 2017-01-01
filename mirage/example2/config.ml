open Mirage

let secrets_dir = "sekrit"

let disk  = direct_kv_ro secrets_dir
and stack = socket_stackv4 [Ipaddr.V4.any]

let packages = [
  package "mirage-clock-unix" ;
  package "mirage-http" ;
  package ~sublibs:["lwt-core"] "cohttp" ;
  package ~sublibs:["mirage"] "tls" ;
  package "tcpip" ;
]
let server = foreign ~deps:[abstract nocrypto] ~packages "Unikernel.Main" @@ stackv4 @-> kv_ro @-> pclock @-> job

let () =
  register "tls-server" [ server $ stack $ disk $ default_posix_clock ]
