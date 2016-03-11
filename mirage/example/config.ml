open Mirage

let secrets_dir = "sekrit"

let build =
  try
    match Sys.getenv "BUILD" with
    | "client" -> `Client
    | "server" -> `Server
  with Not_found -> `Server

let disk = generic_kv_ro secrets_dir

let stack console = generic_stackv4 console tap0

let server =
  foreign ~deps:[abstract nocrypto] "Unikernel.Server" @@ console @-> stackv4 @-> kv_ro @-> job

let client =
  foreign ~deps:[abstract nocrypto] "Unikernel.Client" @@ console @-> stackv4 @-> kv_ro @-> job

let () =
  let platform =
    match get_mode () with
    | `Unix -> "unix"
    | `Xen -> "xen" in
  (* Regrettably, CLOCK can't be dep-injected for now. *)
  add_to_opam_packages [ "mirage-clock-" ^ platform; "tls" ] ;
  add_to_ocamlfind_libraries [ "mirage-clock-" ^ platform; "tls"; "tls.mirage" ] ;
  match build with
  | `Server ->
      register "tls-server" [ server $ default_console $ stack default_console $ disk ]
  | `Client ->
      register "tls-client" [ client $ default_console $ stack default_console $ disk ]
