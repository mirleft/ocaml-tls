open Mirage

let main = foreign "Unikernel.Main" (console @-> stackv4 @-> job)

let net =
  try match Sys.getenv "NET" with
    | "direct" -> `Direct
    | "socket" -> `Socket
    | _        -> `Direct
  with Not_found -> `Socket

let dhcp =
  try match Sys.getenv "ADDR" with
    | "dhcp"   -> `Dhcp
    | "static" -> `Static
  with Not_found -> `Static

let stack console =
  match net, dhcp with
  | `Direct, `Dhcp   -> direct_stackv4_with_dhcp console tap0
  | `Direct, `Static -> direct_stackv4_with_default_ipv4 console tap0
  | `Socket, _       -> socket_stackv4 console [Ipaddr.V4.any]

let () =
  add_to_ocamlfind_libraries
    [ "ipaddr"; "tls" ];

  register "mirage-tls-client" [
    main $ default_console $ stack default_console
  ]
