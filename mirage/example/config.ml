open Mirage

let secrets_dir = "sekrit"

let build =
  try
    match Sys.getenv "BUILD" with
    | "client" -> `Client
    | "server" -> `Server
  with Not_found -> `Server

let disk =
  match get_mode () with
  | `Unix -> direct_kv_ro secrets_dir
  | `Xen  -> crunch secrets_dir

let stack =
  match get_mode () with
  | `Unix -> socket_stackv4 default_console [Ipaddr.V4.any]
  | `Xen  -> direct_stackv4_with_default_ipv4 default_console tap0

let server =
  foreign "Unikernel.Server" @@ console @-> stackv4 @-> kv_ro @-> job

let client =
  foreign "Unikernel.Client" @@ console @-> stackv4 @-> kv_ro @-> job

let () =
  add_to_ocamlfind_libraries ["tls"; "tls.mirage"] ;
  match build with
  | `Server ->
      register "tls-server" [ server $ default_console $ stack $ disk ]
  | `Client ->
      register "tls-client" [ client $ default_console $ stack $ disk ]
