open Mirage

let secrets_dir = "sekrit"

let build =
  try
    match Sys.getenv "BUILD" with
    | "client" -> `Client
    | "server" -> `Server
  with Not_found -> `Server

let disk = generic_kv_ro secrets_dir

let stack = generic_stackv4 tap0

let packages = [ "tls" ]
and libraries = [ "tls" ; "tls.mirage" ]

let server =
  foreign ~deps:[abstract nocrypto] ~libraries ~packages "Unikernel.Server" @@ console @-> stackv4 @-> kv_ro @-> pclock @-> job

let client =
  foreign ~deps:[abstract nocrypto] ~libraries ~packages "Unikernel.Client" @@ console @-> stackv4 @-> kv_ro @-> pclock @-> job

let () =
  match build with
  | `Server ->
      register "tls-server" [ server $ default_console $ stack $ disk $ default_posix_clock ]
  | `Client ->
      register "tls-client" [ client $ default_console $ stack $ disk $ default_posix_clock ]
