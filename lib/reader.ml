open Packet
open Core
open Cstruct

open Sexplib.Conv

type error =
  | TrailingBytes  of string
  | WrongLength    of string
  | Unknown        of string
  | Underflow
  | Overflow       of int
  | UnknownVersion of (int * int)
  | UnknownContent of int
  [@@deriving sexp]

include Control.Or_error_make (struct type err = error end)
type 'a result = ('a, error) Result.result

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

let parse_any_version_exn buf =
  let version = parse_version_int buf in
  match tls_any_version_of_pair version with
  | Some x -> x
  | None   ->
     let major, minor = version in
     raise_unknown @@ "version " ^ string_of_int major ^ "." ^ string_of_int minor

let parse_version = catch parse_version_exn

let parse_any_version = catch parse_any_version_exn

let parse_record buf =
  if len buf < 5 then
    return (`Fragment buf)
  else
    let typ = get_uint8 buf 0
    and version = parse_version_int (shift buf 1)
    in
    match BE.get_uint16 buf 3 with
    | x when x > (1 lsl 14 + 2048) ->
      (* 2 ^ 14 + 2048 for TLSCiphertext
         2 ^ 14 + 1024 for TLSCompressed
         2 ^ 14 for TLSPlaintext *)
      fail (Overflow x)
    | x when 5 + x > len buf -> return (`Fragment buf)
    | x ->
      match
        tls_any_version_of_pair version,
        int_to_content_type typ
      with
      | None, _ -> fail (UnknownVersion version)
      | _, None -> fail (UnknownContent typ)
      | Some version, Some content_type ->
        let payload, rest = split ~start:5 buf x in
        return (`Record (({ content_type ; version }, payload), rest))

let validate_alert (lvl, typ) =
  let open Packet in
  match lvl, typ with
  (* from RFC, find out which ones must be always FATAL
     and report if this does not meet the expectations *)
  | WARNING, UNEXPECTED_MESSAGE -> raise_unknown "unexpected_message must always be fatal"
  | WARNING, BAD_RECORD_MAC -> raise_unknown "bad_record_mac must always be fatal"
  | WARNING, DECRYPTION_FAILED -> raise_unknown "decryption_failed must always be fatal"
  | WARNING, RECORD_OVERFLOW -> raise_unknown "record_overflow must always be fatal"
  | WARNING, DECOMPRESSION_FAILURE -> raise_unknown "decompression_failure must always be fatal"
  | WARNING, HANDSHAKE_FAILURE -> raise_unknown "handshake_failure must always be fatal"
  | WARNING, UNKNOWN_CA -> raise_unknown "unknown_ca must always be fatal"
  | WARNING, ACCESS_DENIED -> raise_unknown "access_denied must always be fatal"
  | WARNING, DECODE_ERROR -> raise_unknown "decode_error must always be fatal"
  | WARNING, DECRYPT_ERROR -> raise_unknown "decrypt_error must always be fatal"
  | WARNING, PROTOCOL_VERSION -> raise_unknown "protocol_version must always be fatal"
  | WARNING, INSUFFICIENT_SECURITY -> raise_unknown "insufficient_security must always be fatal"
  | WARNING, INTERNAL_ERROR -> raise_unknown "internal_error must always be fatal"
  | WARNING, MISSING_EXTENSION -> raise_unknown "missing_extension must always be fatal"
  | WARNING, UNSUPPORTED_EXTENSION -> raise_unknown "unsupported_extension must always be fatal"

  (* those are always warnings *)
  | FATAL, USER_CANCELED -> raise_unknown "user_canceled must always be a warning"
  | FATAL, NO_RENEGOTIATION -> raise_unknown "no_renegotiation must always be a warning"
  | FATAL, END_OF_EARLY_DATA -> raise_unknown "end_of_early_data must always be a warning"

  | lvl, typ -> (lvl, typ)

let parse_alert = catch @@ fun buf ->
  if len buf <> 2 then
    raise_trailing_bytes "after alert"
  else
    let level = get_uint8 buf 0 in
    let typ = get_uint8 buf 1 in
    match int_to_alert_level level, int_to_alert_type typ with
      | (Some lvl, Some msg) -> validate_alert (lvl, msg)
      | (Some _  , None)     -> raise_unknown @@ "alert type " ^ string_of_int typ
      | _                    -> raise_unknown @@ "alert level " ^ string_of_int level

let parse_change_cipher_spec buf =
  match len buf, get_uint8 buf 0 with
  | 1, 1 -> return ()
  | _    -> fail (Unknown "bad change cipher spec message")

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

let parse_compression_method buf =
  let cm = get_uint8 buf 0 in
  (int_to_compression_method cm, shift buf 1)

let parse_compression_methods buf =
  let count = get_uint8 buf 0 in
  parse_count_list parse_compression_method (shift buf 1) [] count

let parse_any_ciphersuite buf =
  let typ = BE.get_uint16 buf 0 in
  (int_to_any_ciphersuite typ, shift buf 2)

let parse_any_ciphersuites buf =
  let count = BE.get_uint16 buf 0 in
  if count mod 2 <> 0 then
    raise_wrong_length "ciphersuite list"
  else
    parse_count_list parse_any_ciphersuite (shift buf 2) [] (count / 2)

let parse_ciphersuite buf =
  match parse_any_ciphersuite buf with
  | None   , buf' -> (None, buf')
  | Some cs, buf' -> match Ciphersuite.any_ciphersuite_to_ciphersuite cs with
                       | None     -> (None, buf')
                       | Some cs' -> (Some cs', buf')

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

let parse_named_group buf =
  let typ = BE.get_uint16 buf 0 in
  (int_to_named_group typ, shift buf 2)

let parse_group buf =
  match parse_named_group buf with
  | Some x, buf -> (Ciphersuite.any_group_to_group x, buf)
  | None, buf -> (None, buf)

let parse_supported_groups buf =
  let count = BE.get_uint16 buf 0 in
  if count mod 2 <> 0 then
    raise_wrong_length "elliptic curve list"
  else
    let cs, rt = parse_count_list parse_named_group (shift buf 2) [] (count / 2) in
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
    let hash_tag = function
      | None -> None
      | Some h -> tag_of_hash_algorithm h
    in
    match hash_tag (int_to_hash_algorithm (get_uint8 buf 0)),
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

let parse_extension buf = function
  | MAX_FRAGMENT_LENGTH ->
     (match parse_fragment_length buf with
      | Some mfl -> `MaxFragmentLength mfl
      | None     -> raise_unknown "maximum fragment length")
  | EC_POINT_FORMATS ->
       let formats = parse_ec_point_format buf in
       `ECPointFormats formats
  | RENEGOTIATION_INFO ->
       let len' = get_uint8 buf 0 in
       if len buf <> len' + 1 then
         raise_trailing_bytes "renegotiation"
       else
         `SecureRenegotiation (sub buf 1 len')
  | EXTENDED_MASTER_SECRET ->
      if len buf > 0 then
         raise_trailing_bytes "extended master secret"
       else
         `ExtendedMasterSecret
  | x -> `UnknownExtension (extension_type_to_int x, buf)

let parse_keyshare_entry buf =
  let parse_share l data =
    let size = BE.get_uint16 data 0 in
    let share, left = split (shift data 2) size in
    match l with
    | 1 ->
      let l = get_uint8 share 0 in
      if len share <> l + 1 then
        raise_trailing_bytes "keyshare"
      else
        (sub share 1 l, left)
    | 2 ->
      let l = BE.get_uint16 share 0 in
      if len share <> l + 2 then
        raise_trailing_bytes "keyshare"
      else
        (sub share 2 l, left)
    | 0 -> (share, left)
    | _ -> raise_unknown "keyshare"
  in
  match parse_named_group buf with
  | Some g, rest ->
     let ksl = ks_len g in
     let share, left = parse_share ksl rest in
     (Some (g, share), left)
  | None, rest ->
     let _, left = parse_share 0 rest in
     (None, left)

let parse_presharedkey buf =
  let len = BE.get_uint16 buf 0 in
  let psk, rest = split (shift buf 2) len in
  (Some psk, rest)

let parse_early_data buf =
  let cfgidlen = BE.get_uint16 buf 0 in
  let configuration_id, rest = split (shift buf 2) cfgidlen in
  match parse_ciphersuite rest with
  | Some ciphersuite, rest ->
     let extlen = BE.get_uint16 rest 0 in
     let extensions, rest = split (shift rest 2) extlen in
     let clen = get_uint8 rest 0 in
     let context, rest = split (shift rest 1) clen in
     if len rest <> 0 then
       raise_trailing_bytes "early_data"
     else
       { configuration_id ; ciphersuite ; extensions ; context }
  | None, _ -> raise_unknown "ciphersuite in early_data"

let parse_client_extension raw =
  let etype = BE.get_uint16 raw 0 in
  let length = BE.get_uint16 raw 2 in
  let buf = sub raw 4 length in
  let data =
    match int_to_extension_type etype with
    | Some SERVER_NAME ->
       (match parse_hostnames buf with
        | [name] -> `Hostname name
        | _      -> raise_unknown "bad server name indication (multiple names)")
    | Some SUPPORTED_GROUPS ->
       let gs = parse_supported_groups buf in
       `SupportedGroups gs
    | Some PADDING ->
       let rec check = function
         | 0 -> `Padding length
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
         `SignatureAlgorithms algos
    | Some KEY_SHARE ->
       let ll = BE.get_uint16 buf 0 in
       if ll + 2 <> len buf then
         raise_unknown "bad key share extension"
       else
         let shares = parse_list parse_keyshare_entry (sub buf 2 ll) [] in
         `KeyShare shares
    | Some PRE_SHARED_KEY ->
       let ll = BE.get_uint16 buf 0 in
       if ll + 2 <> len buf then
         raise_unknown "bad pre_shared_key length"
       else
         let ids = parse_list parse_presharedkey (sub buf 2 ll) [] in
         `PreSharedKey ids
    | Some EARLY_DATA ->
       let ed = parse_early_data buf in
       `EarlyDataIndication ed
    | Some x -> parse_extension buf x
    | None -> `UnknownExtension (etype, buf)
  in
  (Some data, shift raw (4 + length))

let parse_server_extension raw =
  let etype = BE.get_uint16 raw 0 in
  let length = BE.get_uint16 raw 2 in
  let buf = sub raw 4 length in
  let data =
    match int_to_extension_type etype with
    | Some SERVER_NAME ->
       (match parse_hostnames buf with
        | [] -> `Hostname
        | _      -> raise_unknown "bad server name indication (multiple names)")
    | Some KEY_SHARE ->
       (match parse_keyshare_entry buf with
        | _, xs when len xs <> 0 -> raise_trailing_bytes "server keyshare"
        | None, _ -> raise_unknown "keyshare entry"
        | Some (g, ks), _ ->
          match Ciphersuite.any_group_to_group g with
          | Some g -> `KeyShare (g, ks)
          | None -> raise_unknown "keyshare entry")
    | Some PRE_SHARED_KEY ->
       (match parse_presharedkey buf with
        | _, xs when len xs <> 0 -> raise_trailing_bytes "server pre_shared_key"
        | Some psk, _ -> `PreSharedKey psk
        | _ -> raise_unknown "server presharedkey")
    | Some EARLY_DATA ->
       if len buf <> 0 then
         raise_trailing_bytes "server early_data"
       else
         `EarlyDataIndication
    | Some SUPPORTED_GROUPS | Some SIGNATURE_ALGORITHMS | Some PADDING ->
       raise_unknown "invalid extension in server hello!"
    | Some x -> parse_extension buf x
    | None -> `UnknownExtension (etype, buf)
  in
  (Some data, shift raw (4 + length))

let parse_extensions parse_ext buf =
  let length = BE.get_uint16 buf 0 in
  if len buf <> length + 2 then
    raise_trailing_bytes "extensions"
  else
    parse_list parse_ext (sub buf 2 length) []

let parse_client_hello buf =
  let client_version = parse_any_version_exn buf in
  let client_random = sub buf 2 32 in
  let slen = get_uint8 buf 34 in
  let sessionid = if slen = 0 then
                    None
                  else
                    Some (sub buf 35 slen)
  in
  let ciphersuites, rt = parse_any_ciphersuites (shift buf (35 + slen)) in
  let _, rt' = parse_compression_methods rt in
  let extensions = if len rt' == 0 then
                     []
                   else
                     parse_extensions parse_client_extension rt'
  in
  ClientHello { client_version ; client_random ; sessionid ; ciphersuites ; extensions }

let parse_server_hello buf =
  let server_version = parse_version_exn buf in
  let server_random = sub buf 2 32 in
  match server_version with
  | TLS_1_3 ->
     let ciphersuite, rt = match parse_ciphersuite (shift buf 34) with
       | Some x, buf' -> (x, buf')
       | None  , _    -> raise_unknown "ciphersuite"
     in
     let extensions = if len rt == 0 then
                        []
                      else
                        parse_extensions parse_server_extension rt
     in
     ServerHello { server_version ; server_random ; sessionid = None ; ciphersuite ; extensions }
  | TLS_1_0 | TLS_1_1 | TLS_1_2 ->
     let slen = get_uint8 buf 34 in
     let sessionid = if slen = 0 then
                       None
                     else
                       Some (sub buf 35 slen)
     in
     let ciphersuite, rt = match parse_ciphersuite (shift buf (35 + slen)) with
       | Some x, buf' -> (x, buf')
       | None  , _    -> raise_unknown "ciphersuite"
     in
     let rt' = match parse_compression_method rt with
       | Some NULL, buf' -> buf'
       | Some _   , _    -> raise_unknown "unsupported compression method"
       | None     , _    -> raise_unknown "compression method"
     in
     let extensions = if len rt' == 0 then
                        []
                      else
                        parse_extensions parse_server_extension rt'
     in
     ServerHello { server_version ; server_random ; sessionid ; ciphersuite ; extensions }

let parse_certificates_exn buf =
  let parsef buf =
    let len = get_uint24_len buf in
    (Some (sub buf 3 len), shift buf (len + 3))
  in
  let length = get_uint24_len buf in
  if len buf <> length + 3 then
    raise_trailing_bytes "certificates"
  else
    parse_list parsef (sub buf 3 length) []

let parse_certificates = catch @@ parse_certificates_exn

let parse_certificates_1_3_exn buf =
  let clen = get_uint8 buf 0 in
  let context, rt = split (shift buf 1) clen in
  (context, parse_certificates_exn rt)

let parse_certificates_1_3 = catch @@ parse_certificates_1_3_exn

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
    let name = sub buf 2 length in
    (Some name, shift buf (2 + length))
  in
  let calength = BE.get_uint16 buf 0 in
  let cas, rt = split (shift buf 2) calength in
  (parse_list parsef cas [], rt)

let parse_certificate_request_exn buf =
  let certificate_types, buf' = parse_certificate_types buf in
  let certificate_authorities, buf' = parse_cas buf' in
  if len buf' <> 0 then
    raise_trailing_bytes "certificate request"
  else
    (certificate_types, certificate_authorities)

let parse_certificate_request =
  catch parse_certificate_request_exn

let parse_certificate_request_1_2_exn buf =
  let certificate_types, buf' = parse_certificate_types buf in
  let sigs, buf' = parse_hash_sig buf' in
  let cas, buf' = parse_cas buf' in
  if len buf' <> 0 then
    raise_trailing_bytes "certificate request"
  else
    (certificate_types, sigs, cas)

let parse_certificate_request_1_2 =
  catch parse_certificate_request_1_2_exn

let parse_cert_extension buf =
  let olen = get_uint8 buf 0 in
  let oid, rt = split (shift buf 1) olen in
  let vallen = BE.get_uint16 rt 0 in
  let values, rt = split (shift rt 2) vallen in
  (Some (oid, values), rt)

let parse_certificate_request_1_3_exn buf =
  let conlen = get_uint8 buf 0 in
  let context, rt = split (shift buf 1) conlen in
  let sigs, rt = parse_hash_sig rt in
  let cas, rt = parse_cas rt in
  let extlen = BE.get_uint16 rt 0 in
  let extdata, rt = split (shift rt 2) extlen in
  let exts = parse_list parse_cert_extension extdata [] in
  if len rt <> 0 then
    raise_trailing_bytes "certificate request"
  else
    (context, sigs, cas, exts)

let parse_certificate_request_1_3 =
  catch parse_certificate_request_1_3_exn

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
  let hash_tag = function
    | None -> None
    | Some h -> tag_of_hash_algorithm h
  in
  (* XXX project packet-level algorithm_type into something from Ciphersuite. *)
  match hash_tag (int_to_hash_algorithm hash),
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

let parse_hello_retry_request buf =
  let version = parse_version_exn buf in
  let ciphersuite, rt = parse_ciphersuite (shift buf 2) in
  let group, rt = parse_group rt in
  let extensions = parse_extensions parse_server_extension rt in
  match ciphersuite, group with
  | Some ciphersuite, Some selected_group -> { version ; ciphersuite ; selected_group ; extensions }
  | None, _ -> raise_unknown "ciphersuite"
  | _, None -> raise_unknown "selected group"

let parse_server_configuration buf =
  let cfgidlen = BE.get_uint16 buf 0 in
  let configuration_id, rest = split (shift buf 2) cfgidlen in
  let expiration_date, rest = split rest 4 in
  let key_share, rest = parse_keyshare_entry rest in
  let early_data_type = get_uint8 rest 0 in
  let extensions = shift rest 1 in
  match key_share, int_to_early_data_type early_data_type with
  | Some (g, ks), Some early_data_type ->
    (match Ciphersuite.any_group_to_group g with
     | Some g ->
       let key_share = (g, ks) in
       { configuration_id ; expiration_date ; key_share ; early_data_type ; extensions }
     | None -> raise_unknown "key share")
  | None, _ -> raise_unknown "key share"
  | _, None -> raise_unknown "early data type"

let parse_handshake_frame buf =
  if len buf < 4 then
    (None, buf)
  else
    let l = get_uint24_len (shift buf 1) in
    let hslen = l + 4 in
    if len buf >= hslen then
      let hs, rest = split buf hslen in
      (Some hs, rest)
    else
      (None, buf)

let parse_handshake = catch @@ fun buf ->
  let typ = get_uint8 buf 0 in
  let handshake_type = int_to_handshake_type typ in
  let length = get_uint24_len (shift buf 1) in
  if len buf <> length + 4 then
    raise_trailing_bytes "handshake"
  else
    let payload = sub buf 4 length in
    match handshake_type with
    | Some HELLO_REQUEST -> if len payload <> 0 then
                              raise_trailing_bytes "hello request"
                            else
                              HelloRequest
    | Some CLIENT_HELLO -> parse_client_hello payload
    | Some SERVER_HELLO -> parse_server_hello payload
    | Some CERTIFICATE -> Certificate payload
    | Some CERTIFICATE_VERIFY -> CertificateVerify payload
    | Some SERVER_KEY_EXCHANGE -> ServerKeyExchange payload
    | Some SERVER_HELLO_DONE -> if len payload <> 0 then
                                  raise_trailing_bytes "server hello done"
                                else
                                  ServerHelloDone
    | Some CERTIFICATE_REQUEST -> CertificateRequest payload
    | Some CLIENT_KEY_EXCHANGE -> parse_client_key_exchange payload
    | Some FINISHED -> Finished payload
    | Some HELLO_RETRY_REQUEST -> let hrr = parse_hello_retry_request payload in
                                  HelloRetryRequest hrr
    | Some SERVER_CONFIGURATION -> let sc = parse_server_configuration payload in
                                   ServerConfiguration sc
    | Some ENCRYPTED_EXTENSIONS -> let ee = parse_extensions parse_server_extension payload in
                                   EncryptedExtensions ee
    | Some KEY_UPDATE -> if len payload <> 0 then raise_trailing_bytes "key update" else KeyUpdate
    | Some SESSION_TICKET -> SessionTicket payload
    | _  -> raise_unknown @@ "handshake type" ^ string_of_int typ
