open Mirage

let secrets_dir = "sekrit"

let disk =
  match get_mode () with
  | `Unix -> direct_kv_ro secrets_dir
  | `Xen  -> crunch secrets_dir

let server =
  foreign "Unikernel.Server" @@ console @-> stackv4 @-> kv_ro @-> job

let () =
  add_to_ocamlfind_libraries ["tls"; "tls.mirage"] ;
  register "tls-server" [
    server $ default_console
           $ socket_stackv4 default_console [Ipaddr.V4.any]
           $ disk
  ]

