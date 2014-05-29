open Packet
open Core
open Cstruct

type error =
  | TrailingBytes of string
  | WrongLength   of string
  | Unknown       of string
  | Underflow

module Or_error =
  Control.Or_error_make (struct type err = error end)
open Or_error

exception Reader_error of error

let raise_unknown msg        = raise (Reader_error (Unknown msg))
and raise_wrong_length msg   = raise (Reader_error (WrongLength msg))
and raise_trailing_bytes msg = raise (Reader_error (TrailingBytes msg))

let catch f x =
  try return (f x) with
  | Reader_error err   -> fail err
  | Invalid_argument _ -> fail Underflow

let parse_version_int buf =
  let major = get_uint8 buf 0 in
  let minor = get_uint8 buf 1 in
  (major, minor)

let parse_version_exn buf =
  let version = parse_version_int buf in
  match tls_version_of_pair version with
  | Some x -> x
  | None   ->
     let major, minor = version in
     raise_unknown @@ "version " ^ string_of_int major ^ "." ^ string_of_int minor

let parse_version = catch parse_version_exn

(* calling convention is that the buffer length is >= 5! *)
let parse_hdr buf =
  let typ = get_uint8 buf 0 in
  let version = parse_version_int (shift buf 1) in
  let len = BE.get_uint16 buf 3 in
  (int_to_content_type typ, tls_version_of_pair version, len)

let parse_alert = catch @@ fun buf ->
  if len buf <> 2 then
    raise_trailing_bytes "after alert"
  else
    let level = get_uint8 buf 0 in
    let typ = get_uint8 buf 1 in
    match int_to_alert_level level, int_to_alert_type typ with
      | (Some lvl, Some msg) -> (lvl, msg)
      | (Some _  , None)     -> raise_unknown @@ "alert type " ^ string_of_int typ
      | _                    -> raise_unknown @@ "alert level " ^ string_of_int level

let rec parse_count_list parsef buf acc = function
  | 0 -> (List.rev acc, buf)
  | n ->
     match parsef buf with
     | Some elem, buf' -> parse_count_list parsef buf' (elem :: acc) (pred n)
     | None     , buf' -> parse_count_list parsef buf'          acc  (pred n)

let rec parse_list parsef buf acc =
  match len buf with
  | 0 -> List.rev acc
  | _ ->
     match parsef buf with
     | Some elem, buf' -> parse_list parsef buf' (elem :: acc)
     | None     , buf' -> parse_list parsef buf'          acc

let parse_certificate_types buf =
  let parsef buf =
    let byte = get_uint8 buf 0 in
    (int_to_client_certificate_type byte, shift buf 1)
  in
  let count = get_uint8 buf 0 in
  parse_count_list parsef (shift buf 1) [] count

let parse_cas buf =
  let parsef buf =
    let length = BE.get_uint16 buf 0 in
    let name = copy buf 2 length in
    (Some name, shift buf (2 + length))
  in
  let calength = BE.get_uint16 buf 0 in
  if calength <> (len buf) + 2 then
    raise_trailing_bytes "cas"
  else
    parse_list parsef (sub buf 2 calength) []

let parse_certificate_request buf =
  let certificate_types, buf' = parse_certificate_types buf in
  let certificate_authorities = parse_cas buf' in
  CertificateRequest { certificate_types ; certificate_authorities }

let parse_compression_method buf =
  let cm = get_uint8 buf 0 in
  (int_to_compression_method cm, shift buf 1)

let parse_compression_methods buf =
  let count = get_uint8 buf 0 in
  parse_count_list parse_compression_method (shift buf 1) [] count

let parse_ciphersuite buf =
  let typ = BE.get_uint16 buf 0 in
  (Ciphersuite.int_to_ciphersuite typ, shift buf 2)

let parse_ciphersuites buf =
  let count = BE.get_uint16 buf 0 in
  if count mod 2 <> 0 then
    raise_wrong_length "ciphersuite list"
  else
    parse_count_list parse_ciphersuite (shift buf 2) [] (count / 2)

let parse_hostnames buf =
  match len buf with
  | 0 -> []
  | n ->
     let parsef buf =
       let typ = get_uint8 buf 0 in
       let entrylen = BE.get_uint16 buf 1 in
       let rt = shift buf (3 + entrylen) in
       match typ with
       | 0 -> let hostname = copy buf 3 entrylen in
              (Some hostname, rt)
       | _ -> (None, rt)
     in
     let list_length = BE.get_uint16 buf 0 in
     if list_length + 2 <> n then
       raise_trailing_bytes "hostname"
     else
       parse_list parsef (sub buf 2 list_length) []

let parse_fragment_length buf =
  if len buf <> 1 then
    raise_trailing_bytes "fragment length"
  else
    int_to_max_fragment_length (get_uint8 buf 0)

let parse_named_curve buf =
  let typ = BE.get_uint16 buf 0 in
  (int_to_named_curve_type typ, shift buf 2)

let parse_elliptic_curves buf =
  let count = BE.get_uint16 buf 0 in
  if count mod 2 <> 0 then
    raise_wrong_length "elliptic curve list"
  else
    let cs, rt = parse_count_list parse_named_curve (shift buf 2) [] (count / 2) in
    if len rt <> 0 then
      raise_trailing_bytes "elliptic curves"
    else
      cs

let parse_ec_point_format buf =
  let parsef buf =
    let typ = get_uint8 buf 0 in
    (int_to_ec_point_format typ, shift buf 1)
  in
  let count = get_uint8 buf 0 in
  let formats, rt = parse_count_list parsef (shift buf 1) [] count in
  if len rt <> 0 then
    raise_trailing_bytes "ec point formats"
  else
    formats

let parse_hash_sig buf =
  let parsef buf =
    match int_to_hash_algorithm (get_uint8 buf 0),
          int_to_signature_algorithm_type (get_uint8 buf 1)
    with
    | Some h, Some s -> (Some (h, s), shift buf 2)
    | _              -> (None       , shift buf 2)
  in
  let count = BE.get_uint16 buf 0 in
  if count mod 2 <> 0 then
    raise_wrong_length "signature hash"
  else
    parse_count_list parsef (shift buf 2) [] (count / 2)

let parse_extension raw =
  let etype = BE.get_uint16 raw 0 in
  let length = BE.get_uint16 raw 2 in
  let buf = sub raw 4 length in
  let data =
    match int_to_extension_type etype with
    | Some SERVER_NAME ->
       (match parse_hostnames buf with
        | []     -> Hostname None
        | [name] -> Hostname (Some name)
        | _      -> raise_unknown "bad server name indication (multiple names)")
    | Some MAX_FRAGMENT_LENGTH ->
       (match parse_fragment_length buf with
        | Some mfl -> MaxFragmentLength mfl
        | None     -> raise_unknown "maximum fragment length")
    | Some ELLIPTIC_CURVES ->
       let ecc = parse_elliptic_curves buf in
       EllipticCurves ecc
    | Some EC_POINT_FORMATS ->
       let formats = parse_ec_point_format buf in
       ECPointFormats formats
    | Some RENEGOTIATION_INFO ->
       let len' = get_uint8 buf 0 in
       if len buf <> len' + 1 then
         raise_trailing_bytes "renegotiation"
       else
         SecureRenegotiation (sub buf 1 len')
    | Some PADDING ->
       let rec check = function
         | 0 -> Padding length
         | n -> let idx = pred n in
                if get_uint8 buf idx <> 0 then
                  raise_unknown "bad padding in padding extension"
                else
                  check idx
       in
       check length
    | Some SIGNATURE_ALGORITHMS ->
       let algos, rt = parse_hash_sig buf in
       if len rt <> 0 then
         raise_trailing_bytes "signature algorithms"
       else
         SignatureAlgorithms algos
    | _ ->
       UnknownExtension (etype, buf)
  in
  (Some data, shift raw (4 + length))

let parse_extensions buf =
  let length = BE.get_uint16 buf 0 in
  if len buf <> length + 2 then
    raise_trailing_bytes "extensions"
  else
    parse_list parse_extension (sub buf 2 length) []

let parse_hello get_compression get_cipher buf =
  let version = parse_version_exn buf in
  let random = sub buf 2 32 in
  let slen = get_uint8 buf 34 in
  let sessionid = if slen = 0 then
                    None
                  else
                    Some (sub buf 35 slen)
  in
  let ciphersuites, rt = get_cipher (shift buf (35 + slen)) in
  let _, rt' = get_compression rt in
  let extensions = if len rt' == 0 then
                     []
                   else
                     parse_extensions rt'
  in
  { version ; random ; sessionid ; ciphersuites ; extensions }

let parse_client_hello buf =
  let ch = parse_hello parse_compression_methods parse_ciphersuites buf in
  ClientHello ch

let parse_server_hello buf =
  let p_c buf = match parse_compression_method buf with
    | Some x, buf' -> (x, buf')
    | None  , _    -> raise_unknown "compression method"
  in
  let p_c_s buf = match parse_ciphersuite buf with
    | Some x, buf' -> (x, buf')
    | None  , _    -> raise_unknown "ciphersuite"
  in
  let sh = parse_hello p_c p_c_s buf in
  ServerHello sh

let parse_certificates buf =
  let parsef buf =
    let len = get_uint24_len buf in
    (Some (sub buf 3 len), shift buf (len + 3))
  in
  let length = get_uint24_len buf in
  if len buf <> length + 3 then
    raise_trailing_bytes "certificates"
  else
    Certificate (parse_list parsef (sub buf 3 length) [])

let parse_dh_parameters = catch @@ fun raw ->
  let plength = BE.get_uint16 raw 0 in
  let dh_p = sub raw 2 plength in
  let buf = shift raw (2 + plength) in
  let glength = BE.get_uint16 buf 0 in
  let dh_g = sub buf 2 glength in
  let buf = shift buf (2 + glength) in
  let yslength = BE.get_uint16 buf 0 in
  let dh_Ys = sub buf 2 yslength in
  let buf = shift buf (2 + yslength) in
  let rawparams = sub raw 0 (plength + glength + yslength + 6) in
  ({ dh_p ; dh_g ; dh_Ys }, rawparams, buf)

let parse_digitally_signed_exn buf =
  let siglen = BE.get_uint16 buf 0 in
  if len buf <> siglen + 2 then
    raise_trailing_bytes "digitally signed"
  else
    sub buf 2 siglen

let parse_digitally_signed =
  catch parse_digitally_signed_exn

let parse_digitally_signed_1_2 = catch @@ fun buf ->
  (* hash algorithm *)
  let hash = get_uint8 buf 0 in
  (* signature algorithm *)
  let sign = get_uint8 buf 1 in
  (* XXX project packet-level algorithm_type into something from Ciphersuite. *)
  match int_to_hash_algorithm hash,
        int_to_signature_algorithm_type sign with
  | Some hash', Some sign' ->
     let signature = parse_digitally_signed_exn (shift buf 2) in
     (hash', sign', signature)
  | _ , _                  -> raise_unknown "hash or signature algorithm"

let parse_client_key_exchange buf =
  let length = BE.get_uint16 buf 0 in
  if len buf <> length + 2 then
    raise_trailing_bytes "client key exchange"
  else
    ClientKeyExchange (sub buf 2 length)

let parse_handshake = catch @@ fun buf ->
  let typ = get_uint8 buf 0 in
  let handshake_type = int_to_handshake_type typ in
  let length = get_uint24_len (shift buf 1) in
  let payload = sub buf 4 length in
  let hs = match handshake_type with
    | Some HELLO_REQUEST -> if len payload <> 0 then
                              raise_trailing_bytes "hello request"
                            else
                              HelloRequest
    | Some CLIENT_HELLO -> parse_client_hello payload
    | Some SERVER_HELLO -> parse_server_hello payload
    | Some CERTIFICATE -> parse_certificates payload
    | Some SERVER_KEY_EXCHANGE -> ServerKeyExchange payload
    | Some SERVER_HELLO_DONE -> if len payload <> 0 then
                                  raise_trailing_bytes "server hello done"
                                else
                                  ServerHelloDone
    | Some CERTIFICATE_REQUEST -> parse_certificate_request payload
    | Some CLIENT_KEY_EXCHANGE -> parse_client_key_exchange payload
    | Some FINISHED -> Finished payload
    | _  -> raise_unknown @@ "handshake type" ^ string_of_int typ
  in
  let raw, rest = split buf (length + 4) in
  (hs, raw, rest)

