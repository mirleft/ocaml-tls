open Core_kernel.Std
open Async.Std

type priv = X509.t list * Nocrypto.Rsa.priv

type authenticator = X509.Authenticator.a

let (</>) a b = a ^ "/" ^ b

let extension str =
  let n = String.length str in
  let rec scan = function
    | i when i = 0 -> None
    | i when str.[i - 1] = '.' ->
        Some (String.sub str ~pos:i ~len:(n - i))
    | i -> scan (pred i) in
  scan n

let private_of_pems ~cert ~priv_key =
  let open X509.Encoding.Pem in
  (try
     Reader.file_contents cert >>|
     Cstruct.of_string ?allocator:None >>|
     Certificate.of_pem_cstruct
   with Invalid_argument msg ->
     failwithf "Private certificates (%s): %s" cert msg ())
  >>= fun certs ->
  (try
     Reader.file_contents priv_key >>|
     Cstruct.of_string ?allocator:None >>|
     Private_key.of_pem_cstruct1 >>| function `RSA key ->
       key
   with Invalid_argument msg  ->
     failwithf "Private key (%s): %s" priv_key msg ())
  >>| fun pk ->
  (certs, pk)

let certs_of_pem path =
  try
    Reader.file_contents path >>|
    Cstruct.of_string ?allocator:None >>|
    X509.Encoding.Pem.Certificate.of_pem_cstruct
  with Invalid_argument msg ->
    failwithf "Certificates in %s: %s" path msg ()

let certs_of_pem_dir path =
  Sys.readdir path
  >>| Array.to_list
  >>| List.filter ~f:(fun file -> extension file = Some "crt")
  >>= Deferred.List.concat_map ~how:`Parallel ~f:(fun file -> certs_of_pem (path </> file))

let authenticator param =
  let now = Unix.gettimeofday () in
  let of_cas cas =
    X509.Authenticator.chain_of_trust ~time:now cas
  and dotted_hex_to_cs hex =
    Nocrypto.Uncommon.Cs.of_hex
      (String.map ~f:(function ':' -> ' ' | x -> x) hex)
  and fingerp hash fingerprints =
    X509.Authenticator.server_key_fingerprint ~time:now ~hash ~fingerprints
  in
  match param with
  | `Ca_file path -> certs_of_pem path >>| of_cas
  | `Ca_dir path  -> certs_of_pem_dir path >>| of_cas
  | `Key_fingerprints (hash, fps) -> return (fingerp hash fps)
  | `Hex_key_fingerprints (hash, fps) ->
    let fps = List.map ~f:(fun (n, v) -> (n, dotted_hex_to_cs v)) fps in
    return (fingerp hash fps)
  | `No_authentication_I'M_STUPID -> return X509.Authenticator.null
