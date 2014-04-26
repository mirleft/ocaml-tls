
open Lwt

type cert = Tls.X509.Cert.t * Tls.X509.PK.t

let read_file path =
  let open Lwt_io in
  lwt file = open_file ~mode:Input path in
  lwt str  = read file in
  close file >> return (Cstruct.of_string str)

let read_dir path =
  let open Lwt_unix in
  let rec collect acc d =
    match_lwt
      try_lwt readdir d >|= fun e -> Some e with End_of_file -> return None
    with
    | Some e -> collect (e :: acc) d
    | None   -> return acc in
  lwt dir     = opendir path in
  lwt entries = collect [] dir in
  closedir dir >> return entries

let extension str =
  let n = String.length str in
  let rec scan = function
    | i when i = 0         -> None
    | i when str.[i - 1] = '.' ->
        Some (String.sub str i (n - i))
    | i                    -> scan (pred i) in
  scan n

let (</>) a b = a ^ "/" ^ b

let cert_of_pems ~cert ~priv_key =
  lwt cs_cert = read_file cert
  and cs_pk   = read_file priv_key in
  let open Tls.X509 in
  lwt cert =
    try return @@ Cert.of_pem_cstruct1 cs_cert
    with Invalid_argument msg -> fail (Failure ("certificate: " ^ msg))
  and pk   =
    try return @@ PK.of_pem_cstruct1 cs_pk
    with Invalid_argument msg -> fail (Failure ("key: " ^ msg))
  in
  return (cert, pk)

let certs_of_pem path =
  lwt cs_certs = read_file path in
  try
    return @@ Tls.X509.Cert.of_pem_cstruct cs_certs
  with Invalid_argument msg -> fail (Failure ("certificates: " ^ msg))

let certs_of_pem_dir path =
  lwt files = read_dir path in
  files
  |> List.filter (fun file -> extension file = Some "crt")
  |> Lwt_list.map_p (fun file -> certs_of_pem (path </> file))
  >|= List.concat

let validator = function
  | `Ca_file path ->
      certs_of_pem path >|= fun cas ->
        Tls.X509.Validator.chain_of_trust ~time:0 cas
  | `Ca_dir path ->
      certs_of_pem_dir path >|= fun cas ->
        Tls.X509.Validator.chain_of_trust ~time:0 cas
  | `No_validation -> return Tls.X509.Validator.null

