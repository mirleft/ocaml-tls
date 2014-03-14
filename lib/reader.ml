open Packet
open Core

let parse_hdr buf =
  let typ = int_to_content_type (get_tls_h_content_type buf) in
  let major = get_tls_h_major_version buf in
  let minor = get_tls_h_minor_version buf in
  let version = (major, minor) in
  let len = get_tls_h_length buf in
  let payload = Cstruct.shift buf 5 in
  match typ with
  | Some content_type -> ( Some { content_type; version }, payload, len)
  | None              -> ( None, payload, len)

let parse_alert buf =
  let level = Cstruct.get_uint8 buf 0 in
  let typ = Cstruct.get_uint8 buf 1 in
  match int_to_alert_level level, int_to_alert_type typ with
    | (Some lvl, Some msg) -> Some (lvl, msg)
    | _                    -> None

let rec parse_certificate_types buf acc = function
  | 0 -> acc
  | n -> let typ = Cstruct.get_uint8 buf 0 in
         match int_to_client_certificate_type typ with
         | Some x ->
            parse_certificate_types (Cstruct.shift buf 1) (x :: acc) (n - 1)
         | None -> failwith @@ "unsupported certificate type: " ^ string_of_int typ

let rec parse_cas buf acc =
  match (Cstruct.len buf) with
  | 0 -> acc
  | n ->
     let len = Cstruct.BE.get_uint16 buf 0 in
     let name = Cstruct.copy buf 2 len in
     parse_cas (Cstruct.shift buf (2 + len)) (name :: acc)

let parse_certificate_request buf =
  let typeslen = Cstruct.get_uint8 buf 0 in
  let certificate_types = parse_certificate_types (Cstruct.shift buf 1) [] typeslen in
  let buf = Cstruct.shift buf (1 + typeslen) in
  let calength = Cstruct.BE.get_uint16 buf 0 in
  let certificate_authorities = parse_cas (Cstruct.sub buf 2 calength) [] in
  CertificateRequest { certificate_types ; certificate_authorities }

let parse_compression_method buf =
  let cm = Cstruct.get_uint8 buf 0 in
  match int_to_compression_method cm with
  | Some x -> (x, 1)
  | None   -> failwith @@ "unsupported compression method: " ^ string_of_int cm

let parse_compression_methods buf =
  let rec go buf acc = function
    | 0 -> acc
    | n ->
       let cm, b = parse_compression_method buf in
       go (Cstruct.shift buf b) (cm :: acc) (n - 1)
  in
  let len = Cstruct.get_uint8 buf 0 in
  let methods = go (Cstruct.shift buf 1) [] len in
  (methods, len + 1)

let parse_ciphersuite buf =
  let typ = Cstruct.BE.get_uint16 buf 0 in
  match Ciphersuite.int_to_ciphersuite typ with
  | Some x -> (x, 2)
  | None -> failwith @@ "unknown ciphersuite: " ^ string_of_int typ

let parse_ciphersuites buf =
  let rec go buf acc = function
    | 0 -> acc
    | n ->
       let suite, l = parse_ciphersuite buf in
       go (Cstruct.shift buf l) (suite :: acc) (n - 1)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  let suites = go (Cstruct.shift buf 2) [] (len / 2) in
  (List.rev suites, len + 2)

let parse_hostnames buf =
  if Cstruct.len buf > 1 then
    let list_length = Cstruct.BE.get_uint16 buf 0 in
    let rec go buf acc =
      match (Cstruct.len buf) with
      | 0 -> acc
      | n ->
         let name_type = Cstruct.get_uint8 buf 0 in
         match name_type with
         | 0 ->
            let hostname_length = Cstruct.BE.get_uint16 buf 1 in
            go (Cstruct.shift buf (3 + hostname_length)) ((Cstruct.copy buf 3 hostname_length) :: acc)
         | _ -> failwith @@ "unknown name_type: " ^ string_of_int name_type
    in
    go (Cstruct.sub buf 2 list_length) []
  else
    []

let parse_fragment_length buf =
  int_to_max_fragment_length (Cstruct.get_uint8 buf 0)

let parse_named_curve buf =
  let typ = Cstruct.BE.get_uint16 buf 0 in
  match int_to_named_curve_type typ with
  | Some x -> x
  | None -> failwith @@ "unknown named curve: " ^ string_of_int typ

let parse_elliptic_curves buf =
  let rec go buf acc = match (Cstruct.len buf) with
    | 0 -> acc
    | n -> go (Cstruct.shift buf 2) (parse_named_curve buf :: acc)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  go (Cstruct.sub buf 2 len) []

let parse_ec_point_format buf =
  let rec go buf acc = match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let typ = Cstruct.get_uint8 buf 0 in
       match int_to_ec_point_format typ with
         | Some fmt -> go (Cstruct.shift buf 1) (fmt :: acc)
         | None     -> failwith @@ "unknown ec point format: " ^ string_of_int typ
  in
  let len = Cstruct.get_uint8 buf 0 in
  go (Cstruct.sub buf 1 len) []

let parse_extension buf =
  let etype = Cstruct.BE.get_uint16 buf 0 in
  let len = Cstruct.BE.get_uint16 buf 2 in
  let buf = Cstruct.sub buf 4 len in
  let data = match (int_to_extension_type etype) with
    | Some SERVER_NAME ->
       (match parse_hostnames buf with
        | [] -> Hostname None
        | [name] -> Hostname (Some name)
        | _ -> failwith @@ "bad server_name extension")
    | Some MAX_FRAGMENT_LENGTH -> MaxFragmentLength (parse_fragment_length buf)
    | Some ELLIPTIC_CURVES -> EllipticCurves (parse_elliptic_curves buf)
    | Some EC_POINT_FORMATS -> ECPointFormats (parse_ec_point_format buf)
    | Some RENEGOTIATION_INFO -> SecureRenegotiation (Cstruct.shift buf 1)
    | Some x -> Unsupported x
    | None -> failwith @@ "unknown extension: " ^ string_of_int etype
  in
  (data, 4 + len)

let parse_extensions buf =
  let rec go buf acc =
    match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let extension, esize = parse_extension buf in
       go (Cstruct.shift buf esize) (extension :: acc)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  (go (Cstruct.sub buf 2 len) [], 2 + len)

let parse_hello get_compression get_cipher buf =
  let major = get_c_hello_major_version buf in
  let minor = get_c_hello_minor_version buf in
  let version = (major, minor) in
  let random = get_c_hello_random buf in
  let slen = Cstruct.get_uint8 buf 34 in
  let sessionid = if slen = 0 then None else Some (Cstruct.sub buf 35 slen) in
  let ciphersuites, clen = get_cipher (Cstruct.shift buf (35 + slen)) in
  let _, dlen = get_compression (Cstruct.shift buf (35 + slen + clen)) in
  let extensions, _ =
    if Cstruct.len buf > (35 + slen + clen + dlen) then
      parse_extensions (Cstruct.shift buf (35 + slen + clen + dlen))
    else
      ([], 0)
  in
  { version ; random ; sessionid ; ciphersuites ; extensions }

let parse_client_hello buf =
  ClientHello (parse_hello parse_compression_methods parse_ciphersuites buf)

let parse_server_hello buf =
  ServerHello (parse_hello parse_compression_method parse_ciphersuite buf)

let parse_certificate buf =
  let len = get_uint24_len buf in
  ((Cstruct.sub buf 3 len), len + 3)

(* hahaha get some, geddit?? *)
(*
let get_some prs buf =
  let go buf = match (Cstruct.len buf) with
    | 0 -> []
    | n -> let x, buf' = prs buf in x :: go buf' in
  let len = get_uint24_len buf in
  go (Cstruct.sub buf 3 len)
*)

let parse_certificates buf =
  let rec go buf acc =
            match (Cstruct.len buf) with
            | 0 -> List.rev acc
            | n -> let cert, size = parse_certificate buf in
                   go (Cstruct.shift buf size) (cert :: acc)
  in
  let len = get_uint24_len buf in
  let cs = go (Cstruct.sub buf 3 len) [] in
  Certificate cs

let parse_rsa_parameters buf =
  let mlength = Cstruct.BE.get_uint16 buf 0 in
  let rsa_modulus = Cstruct.sub buf 2 mlength in
  let buf = Cstruct.shift buf (2 + mlength) in
  let elength = Cstruct.BE.get_uint16 buf 0 in
  let rsa_exponent = Cstruct.sub buf 2 elength in
  ({ rsa_modulus ; rsa_exponent }, 4 + mlength + elength)

let parse_dh_parameters_and_signature raw =
  let plength = Cstruct.BE.get_uint16 raw 0 in
  let dh_p = Cstruct.sub raw 2 plength in
  let buf = Cstruct.shift raw (2 + plength) in
  let glength = Cstruct.BE.get_uint16 buf 0 in
  let dh_g = Cstruct.sub buf 2 glength in
  let buf = Cstruct.shift buf (2 + glength) in
  let yslength = Cstruct.BE.get_uint16 buf 0 in
  let dh_Ys = Cstruct.sub buf 2 yslength in
  let buf = Cstruct.shift buf (2 + yslength) in
  let siglen = Cstruct.BE.get_uint16 buf 0 in
  let sign = Cstruct.sub buf 2 siglen in
  ({ dh_p ; dh_g; dh_Ys }, sign,
   Cstruct.sub raw 0 (plength + glength + yslength + 6) )

let parse_ec_curve buf =
  let al = Cstruct.get_uint8 buf 0 in
  let a = Cstruct.sub buf 1 al in
  let buf = Cstruct.shift buf (1 + al) in
  let bl = Cstruct.get_uint8 buf 0 in
  let b = Cstruct.sub buf 1 bl in
  let buf = Cstruct.shift buf (1 + bl) in
  ({ a ; b }, buf)

let parse_ec_prime_parameters buf =
  let plen = Cstruct.get_uint8 buf 0 in
  let prime = Cstruct.sub buf 1 plen in
  let buf = Cstruct.shift buf (1 + plen) in
  let curve, buf = parse_ec_curve buf in
  let blen = Cstruct.get_uint8 buf 0 in
  let base = Cstruct.sub buf 1 blen in
  let buf = Cstruct.shift buf (1 + blen) in
  let olen = Cstruct.get_uint8 buf 0 in
  let order = Cstruct.sub buf 1 olen in
  let buf = Cstruct.shift buf (1 + olen) in
  let cofactorlength = Cstruct.get_uint8 buf 0 in
  let cofactor = Cstruct.sub buf 1 cofactorlength in
  let buf = Cstruct.shift buf (1 + cofactorlength) in
  let publiclen = Cstruct.get_uint8 buf 0 in
  let public = Cstruct.sub buf 1 publiclen in
  let buf = Cstruct.shift buf (1 + publiclen) in
  ({ prime ; curve ; base ; order ; cofactor ; public }, buf)

let parse_ec_char_parameters buf =
  let m = Cstruct.BE.get_uint16 buf 0 in
  let typ = Cstruct.get_uint8 buf 2 in
  let basis = match int_to_ec_basis_type typ with
    | Some x -> x
    | None -> failwith @@ "unknown basis type: " ^ string_of_int typ
  in
  let buf = Cstruct.shift buf 3 in
  let ks, buf = match basis with
    | TRINOMIAL ->
       let len = Cstruct.get_uint8 buf 0 in
       ([Cstruct.sub buf 1 len], Cstruct.shift buf (len + 1))
    | PENTANOMIAL ->
       let k1len = Cstruct.get_uint8 buf 0 in
       let k1 = Cstruct.sub buf 1 k1len in
       let buf = Cstruct.shift buf (k1len + 1) in
       let k2len = Cstruct.get_uint8 buf 0 in
       let k2 = Cstruct.sub buf 1 k2len in
       let buf = Cstruct.shift buf (k2len + 1) in
       let k3len = Cstruct.get_uint8 buf 0 in
       let k3 = Cstruct.sub buf 1 k3len in
       ([k1; k2; k3], Cstruct.shift buf (k3len + 1))
  in
  let curve, buf = parse_ec_curve buf in
  let blen = Cstruct.get_uint8 buf 0 in
  let base = Cstruct.sub buf 1 blen in
  let buf = Cstruct.shift buf (1 + blen) in
  let olen = Cstruct.get_uint8 buf 0 in
  let order = Cstruct.sub buf 1 olen in
  let buf = Cstruct.shift buf (1 + olen) in
  let cofactorlength = Cstruct.get_uint8 buf 0 in
  let cofactor = Cstruct.sub buf 1 cofactorlength in
  let buf = Cstruct.shift buf (1 + cofactorlength) in
  let publiclen = Cstruct.get_uint8 buf 0 in
  let public = Cstruct.sub buf 1 publiclen in
  let buf = Cstruct.shift buf (1 + publiclen) in
  ({ m ; basis ; ks ; curve ; base ; order ; cofactor ; public }, buf)

let parse_ec_parameters buf =
  let pbuf = Cstruct.shift buf 1 in
  let typ = Cstruct.get_uint8 buf 0 in
  match int_to_ec_curve_type typ with
  | Some EXPLICIT_PRIME ->
     let ep, buf = parse_ec_prime_parameters pbuf in
     (ExplicitPrimeParameters ep, buf)
  | Some EXPLICIT_CHAR2 ->
     let ec, buf = parse_ec_char_parameters pbuf in
     (ExplicitCharParameters ec, buf)
  | Some NAMED_CURVE ->
     let curve = parse_named_curve pbuf in
     let plen = Cstruct.get_uint8 buf 2 in
     let public = Cstruct.sub buf 3 plen in
     (NamedCurveParameters (curve, public), Cstruct.shift buf (3 + plen))
  | _ -> failwith @@ "unkown curve type: " ^ string_of_int typ

let parse_client_key_exchange buf =
  let len = Cstruct.BE.get_uint16 buf 0 in
  ClientKeyExchange (Cstruct.sub buf 2 len)

let parse_handshake buf =
  let typ = Cstruct.get_uint8 buf 0 in
  let handshake_type = int_to_handshake_type typ in
  let len = get_uint24_len (Cstruct.shift buf 1) in
  let payload = Cstruct.sub buf 4 len in
  match handshake_type with
    | Some HELLO_REQUEST -> Some HelloRequest
    | Some CLIENT_HELLO -> Some (parse_client_hello payload)
    | Some SERVER_HELLO -> Some (parse_server_hello payload)
    | Some CERTIFICATE -> Some (parse_certificates payload)
    | Some SERVER_KEY_EXCHANGE -> Some (ServerKeyExchange payload)
    | Some SERVER_HELLO_DONE -> Some ServerHelloDone
    | Some CERTIFICATE_REQUEST -> Some (parse_certificate_request payload)
    | Some CLIENT_KEY_EXCHANGE -> Some (parse_client_key_exchange payload)
    | Some FINISHED -> Some (Finished (Cstruct.sub payload 0 12))
    | _ -> None

