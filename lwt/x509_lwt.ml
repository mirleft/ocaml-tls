
open Lwt

type priv = X509.Cert.t list * X509.PK.t

type authenticator = X509.Authenticator.t


let failure msg = fail @@ Failure msg

let catch_invalid_arg th h =
  try_lwt th with
  | Invalid_argument msg -> h msg
  | exn                  -> fail exn


let (</>) a b = a ^ "/" ^ b

let o f g x = f (g x)

let read_file path =
  let open Lwt_io in
  lwt file = open_file ~mode:Input path in
  lwt cs   = read file >|= Cstruct.of_string in
  close file >> return cs

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
    | i when i = 0 -> None
    | i when str.[i - 1] = '.' ->
        Some (String.sub str i (n - i))
    | i -> scan (pred i) in
  scan n


let private_of_pems ~cert ~priv_key =
  lwt certs =
    catch_invalid_arg
      (read_file cert >|= X509.Cert.of_pem_cstruct)
      (o failure @@ Printf.sprintf "Private certificates (%s): %s" cert)
  and pk =
    catch_invalid_arg
      (read_file priv_key >|= X509.PK.of_pem_cstruct1)
      (o failure @@ Printf.sprintf "Private key (%s): %s" priv_key)
  in return (certs, pk)

let certs_of_pem path =
  catch_invalid_arg
    (read_file path >|= X509.Cert.of_pem_cstruct)
    (o failure @@ Printf.sprintf "Certificates in %s: %s" path)

let certs_of_pem_dir path =
  read_dir path
  >|= List.filter (fun file -> extension file = Some "crt")
  >>= Lwt_list.map_p (fun file -> certs_of_pem (path </> file))
  >|= List.concat

let authenticator param =
  let now = Unix.gettimeofday () in
  let of_cas cas =
    X509.Authenticator.chain_of_trust ~time:now cas
  in
  let fingerp hash fingerprints =
    X509.Authenticator.server_fingerprint ~time:now ~hash ~fingerprints
  in
  match param with
  | `Ca_file path -> certs_of_pem path >|= of_cas
  | `Ca_dir path  -> certs_of_pem_dir path >|= of_cas
  | `Fingerprints (hash, fps) -> return (fingerp hash fps)
  | `Hex_fingerprints (hash, fps) ->
    let fps = List.map (fun (n, v) -> (n, X509.Cs.dotted_hex_to_cs v)) fps in
    return (fingerp hash fps)
  | `No_authentication_I'M_STUPID -> return X509.Authenticator.null
