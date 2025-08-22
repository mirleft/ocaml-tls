(** Magic numbers of the TLS protocol. *)

(* HACK: 24 bits type not in cstruct *)
let get_uint24_len ~off buf =
  (String.get_uint16_be buf off) * 0x100 + (String.get_uint8 buf (off + 2))

let set_uint24_len ~off buf num =
  Bytes.set_uint16_be buf off (num / 0x100);
  Bytes.set_uint8 buf (off + 2) (num mod 0x100)

(* TLS record content type *)
type content_type =
  | CHANGE_CIPHER_SPEC
  | ALERT
  | HANDSHAKE
  | APPLICATION_DATA

let content_type_to_int = function
  | CHANGE_CIPHER_SPEC -> 20
  | ALERT -> 21
  | HANDSHAKE -> 22
  | APPLICATION_DATA -> 23
and int_to_content_type = function
  | 20 -> Some CHANGE_CIPHER_SPEC
  | 21 -> Some ALERT
  | 22 -> Some HANDSHAKE
  | 23 -> Some APPLICATION_DATA
  | _ -> None

let content_type_to_string = function
  | CHANGE_CIPHER_SPEC -> "change cipher spec"
  | ALERT -> "alert"
  | HANDSHAKE -> "handshake"
  | APPLICATION_DATA -> "application data"

let pp_content_type ppf ct =
  Fmt.string ppf (content_type_to_string ct)

(* TLS alert level *)
type alert_level =
  | WARNING
  | FATAL

let pp_alert_level ppf = function
  | WARNING -> Fmt.string ppf "warning"
  | FATAL -> Fmt.string ppf "fatal"

let alert_level_to_int = function
  | WARNING -> 1
  | FATAL -> 2
and int_to_alert_level = function
  | 1 -> Some WARNING
  | 2 -> Some FATAL
  | _ -> None

(* TLS alert types *)
type alert_type =
  | CLOSE_NOTIFY                    [@id 0]   (*RFC5246*)
  | UNEXPECTED_MESSAGE              [@id 10]  (*RFC5246*)
  | BAD_RECORD_MAC                  [@id 20]  (*RFC5246*)
  | RECORD_OVERFLOW                 [@id 22]  (*RFC5246*)
  | HANDSHAKE_FAILURE               [@id 40]  (*RFC5246*)
  | BAD_CERTIFICATE                 [@id 42]  (*RFC5246*)
  | CERTIFICATE_EXPIRED             [@id 45]  (*RFC5246*)
  | CERTIFICATE_UNKNOWN             [@id 46]  (*RFC5246*)
  | DECODE_ERROR                    [@id 50]  (*RFC5246*)
  | PROTOCOL_VERSION                [@id 70]  (*RFC5246*)
  | INAPPROPRIATE_FALLBACK          [@id 86]  (*draft-ietf-tls-downgrade-scsv*)
  | USER_CANCELED                   [@id 90]  (*RFC5246*)
  | NO_RENEGOTIATION                [@id 100] (*RFC5246*)
  | MISSING_EXTENSION               [@id 109] (*RFC8446*)
  | UNSUPPORTED_EXTENSION           [@id 110] (*RFC5246*)
  | UNRECOGNIZED_NAME               [@id 112] (*RFC6066*)
  | NO_APPLICATION_PROTOCOL         [@id 120] (*RFC7301*)
  | UNKNOWN of int

let alert_type_to_string = function
  | CLOSE_NOTIFY -> "close notify"
  | UNEXPECTED_MESSAGE -> "unexpected message"
  | BAD_RECORD_MAC -> "bad record mac"
  | RECORD_OVERFLOW -> "record overflow"
  | HANDSHAKE_FAILURE -> "handshake failure"
  | BAD_CERTIFICATE -> "bad certificate"
  | CERTIFICATE_EXPIRED -> "certificate expired"
  | CERTIFICATE_UNKNOWN -> "certificate unknown"
  | DECODE_ERROR -> "decode error"
  | PROTOCOL_VERSION -> "protocol version"
  | INAPPROPRIATE_FALLBACK -> "inappropriate fallback"
  | USER_CANCELED -> "user canceled"
  | NO_RENEGOTIATION -> "no renegotiation"
  | MISSING_EXTENSION -> "missing extension"
  | UNSUPPORTED_EXTENSION -> "unsupported extension"
  | UNRECOGNIZED_NAME -> "unrecognized name"
  | NO_APPLICATION_PROTOCOL -> "no application protocol"
  | UNKNOWN x -> "unknown " ^ string_of_int x

let alert_type_to_int = function
  | CLOSE_NOTIFY                    -> 0   (*RFC5246*)
  | UNEXPECTED_MESSAGE              -> 10  (*RFC5246*)
  | BAD_RECORD_MAC                  -> 20  (*RFC5246*)
  | RECORD_OVERFLOW                 -> 22  (*RFC5246*)
  | HANDSHAKE_FAILURE               -> 40  (*RFC5246*)
  | BAD_CERTIFICATE                 -> 42  (*RFC5246*)
  | CERTIFICATE_EXPIRED             -> 45  (*RFC5246*)
  | CERTIFICATE_UNKNOWN             -> 46  (*RFC5246*)
  | DECODE_ERROR                    -> 50  (*RFC5246*)
  | PROTOCOL_VERSION                -> 70  (*RFC5246*)
  | INAPPROPRIATE_FALLBACK          -> 86  (*draft-ietf-tls-downgrade-scsv*)
  | USER_CANCELED                   -> 90  (*RFC5246*)
  | NO_RENEGOTIATION                -> 100 (*RFC5246*)
  | MISSING_EXTENSION               -> 109 (*RFC8446*)
  | UNSUPPORTED_EXTENSION           -> 110 (*RFC5246*)
  | UNRECOGNIZED_NAME               -> 112 (*RFC6066*)
  | NO_APPLICATION_PROTOCOL         -> 120 (*RFC7301*)
  | UNKNOWN x -> x
and int_to_alert_type = function
  | 0 -> CLOSE_NOTIFY
  | 10 -> UNEXPECTED_MESSAGE
  | 20 -> BAD_RECORD_MAC
  | 22 -> RECORD_OVERFLOW
  | 40 -> HANDSHAKE_FAILURE
  | 42 -> BAD_CERTIFICATE
  | 45 -> CERTIFICATE_EXPIRED
  | 46 -> CERTIFICATE_UNKNOWN
  | 50 -> DECODE_ERROR
  | 70 -> PROTOCOL_VERSION
  | 86 -> INAPPROPRIATE_FALLBACK
  | 90 -> USER_CANCELED
  | 100 -> NO_RENEGOTIATION
  | 109 -> MISSING_EXTENSION
  | 110 -> UNSUPPORTED_EXTENSION
  | 112 -> UNRECOGNIZED_NAME
  | 120 -> NO_APPLICATION_PROTOCOL
  | x -> UNKNOWN x

let pp_alert ppf (lvl, typ) =
  Fmt.pf ppf "ALERT %a %s" pp_alert_level lvl (alert_type_to_string typ)

(* TLS handshake type *)
type handshake_type =
  | HELLO_REQUEST        [@id 0]
  | CLIENT_HELLO         [@id 1]
  | SERVER_HELLO         [@id 2]
  | HELLO_VERIFY_REQUEST [@id 3] (*RFC6347*)
  | SESSION_TICKET       [@id 4] (*RFC4507, RFC8446*)
  | END_OF_EARLY_DATA    [@id 5] (*RFC8446*)
  | ENCRYPTED_EXTENSIONS [@id 8] (*RFC8446*)
  | CERTIFICATE          [@id 11]
  | SERVER_KEY_EXCHANGE  [@id 12]
  | CERTIFICATE_REQUEST  [@id 13]
  | SERVER_HELLO_DONE    [@id 14]
  | CERTIFICATE_VERIFY   [@id 15]
  | CLIENT_KEY_EXCHANGE  [@id 16]
  | FINISHED             [@id 20]
  | CERTIFICATE_URL      [@id 21] (*RFC4366*)
  | CERTIFICATE_STATUS   [@id 22] (*RFC4366*)
  | SUPPLEMENTAL_DATA    [@id 23] (*RFC4680*)
  | KEY_UPDATE           [@id 24] (*RFC8446*)
  | MESSAGE_HASH         [@id 254] (*RFC8446*)

let handshake_type_to_int = function
  | HELLO_REQUEST        -> 0
  | CLIENT_HELLO         -> 1
  | SERVER_HELLO         -> 2
  | HELLO_VERIFY_REQUEST -> 3 (*RFC6347*)
  | SESSION_TICKET       -> 4 (*RFC4507, RFC8446*)
  | END_OF_EARLY_DATA    -> 5 (*RFC8446*)
  | ENCRYPTED_EXTENSIONS -> 8 (*RFC8446*)
  | CERTIFICATE          -> 11
  | SERVER_KEY_EXCHANGE  -> 12
  | CERTIFICATE_REQUEST  -> 13
  | SERVER_HELLO_DONE    -> 14
  | CERTIFICATE_VERIFY   -> 15
  | CLIENT_KEY_EXCHANGE  -> 16
  | FINISHED             -> 20
  | CERTIFICATE_URL      -> 21 (*RFC4366*)
  | CERTIFICATE_STATUS   -> 22 (*RFC4366*)
  | SUPPLEMENTAL_DATA    -> 23 (*RFC4680*)
  | KEY_UPDATE           -> 24 (*RFC8446*)
  | MESSAGE_HASH         -> 254 (*RFC8446*)
and int_to_handshake_type = function
  | 0 -> Some HELLO_REQUEST
  | 1 -> Some CLIENT_HELLO
  | 2 -> Some SERVER_HELLO
  | 3 -> Some HELLO_VERIFY_REQUEST
  | 4 -> Some SESSION_TICKET
  | 5 -> Some END_OF_EARLY_DATA
  | 8 -> Some ENCRYPTED_EXTENSIONS
  | 11 -> Some CERTIFICATE
  | 12 -> Some SERVER_KEY_EXCHANGE
  | 13 -> Some CERTIFICATE_REQUEST
  | 14 -> Some SERVER_HELLO_DONE
  | 15 -> Some CERTIFICATE_VERIFY
  | 16 -> Some CLIENT_KEY_EXCHANGE
  | 20 -> Some FINISHED
  | 21 -> Some CERTIFICATE_URL
  | 22 -> Some CERTIFICATE_STATUS
  | 23 -> Some SUPPLEMENTAL_DATA
  | 24 -> Some KEY_UPDATE
  | 254 -> Some MESSAGE_HASH
  | _ -> None

(* TLS certificate types *)
type client_certificate_type =
  | RSA_SIGN                  [@id 1]  (*RFC5246*)
  | ECDSA_SIGN                [@id 64] (*RFC4492*)

let client_certificate_type_to_int = function
  | RSA_SIGN                  -> 1  (*RFC5246*)
  | ECDSA_SIGN                -> 64 (*RFC4492*)
and int_to_client_certificate_type = function
  | 1 -> Some RSA_SIGN
  | 64 -> Some ECDSA_SIGN
  | _ -> None

(* TLS compression methods, used in hello packets *)
type compression_method =
  | NULL    [@id 0]

let compression_method_to_int = function
  | NULL -> 0
and int_to_compression_method = function
  | 0 -> Some NULL
  | _ -> None

(* TLS extensions in hello packets from RFC 6066, formerly RFC 4366 *)
type extension_type =
  | SERVER_NAME                            [@id 0]
  | MAX_FRAGMENT_LENGTH                    [@id 1]
  | SUPPORTED_GROUPS                       [@id 10] (*RFC4492, RFC8446*)
  | EC_POINT_FORMATS                       [@id 11] (*RFC4492*)
  | SIGNATURE_ALGORITHMS                   [@id 13] (*RFC5246*)
  | APPLICATION_LAYER_PROTOCOL_NEGOTIATION [@id 16] (*RFC7301*)
  | PADDING                                [@id 21] (*RFC7685*)
  | EXTENDED_MASTER_SECRET                 [@id 23] (*RFC7627*)
  | SESSION_TICKET                         [@id 35] (*RFC4507*)
  | PRE_SHARED_KEY                         [@id 41] (*RFC8446*)
  | EARLY_DATA                             [@id 42] (*RFC8446*)
  | SUPPORTED_VERSIONS                     [@id 43] (*RFC8446*)
  | COOKIE                                 [@id 44] (*RFC8446*)
  | PSK_KEY_EXCHANGE_MODES                 [@id 45] (*RFC8446*)
  | CERTIFICATE_AUTHORITIES                [@id 47] (*RFC8446*)
  | POST_HANDSHAKE_AUTH                    [@id 49] (*RFC8446*)
  | KEY_SHARE                              [@id 51] (*RFC8446*)
  | RENEGOTIATION_INFO                     [@id 0xFF01] (*RFC5746*)

let extension_type_to_int = function
  | SERVER_NAME                            -> 0
  | MAX_FRAGMENT_LENGTH                    -> 1
  | SUPPORTED_GROUPS                       -> 10 (*RFC4492, RFC8446*)
  | EC_POINT_FORMATS                       -> 11 (*RFC4492*)
  | SIGNATURE_ALGORITHMS                   -> 13 (*RFC5246*)
  | APPLICATION_LAYER_PROTOCOL_NEGOTIATION -> 16 (*RFC7301*)
  | PADDING                                -> 21 (*RFC7685*)
  | EXTENDED_MASTER_SECRET                 -> 23 (*RFC7627*)
  | SESSION_TICKET                         -> 35 (*RFC4507*)
  | PRE_SHARED_KEY                         -> 41 (*RFC8446*)
  | EARLY_DATA                             -> 42 (*RFC8446*)
  | SUPPORTED_VERSIONS                     -> 43 (*RFC8446*)
  | COOKIE                                 -> 44 (*RFC8446*)
  | PSK_KEY_EXCHANGE_MODES                 -> 45 (*RFC8446*)
  | CERTIFICATE_AUTHORITIES                -> 47 (*RFC8446*)
  | POST_HANDSHAKE_AUTH                    -> 49 (*RFC8446*)
  | KEY_SHARE                              -> 51 (*RFC8446*)
  | RENEGOTIATION_INFO                     -> 0xFF01 (*RFC5746*)
and int_to_extension_type = function
  | 0 -> Some SERVER_NAME
  | 1 -> Some MAX_FRAGMENT_LENGTH
  | 10 -> Some SUPPORTED_GROUPS
  | 11 -> Some EC_POINT_FORMATS
  | 13 -> Some SIGNATURE_ALGORITHMS
  | 16 -> Some APPLICATION_LAYER_PROTOCOL_NEGOTIATION
  | 21 -> Some PADDING
  | 23 -> Some EXTENDED_MASTER_SECRET
  | 35 -> Some SESSION_TICKET
  | 41 -> Some PRE_SHARED_KEY
  | 42 -> Some EARLY_DATA
  | 43 -> Some SUPPORTED_VERSIONS
  | 44 -> Some COOKIE
  | 45 -> Some PSK_KEY_EXCHANGE_MODES
  | 47 -> Some CERTIFICATE_AUTHORITIES
  | 49 -> Some POST_HANDSHAKE_AUTH
  | 51 -> Some KEY_SHARE
  | 0xFF01 -> Some RENEGOTIATION_INFO
  | _ -> None

let extension_type_to_string et = string_of_int (extension_type_to_int et)

(* TLS maximum fragment length *)
type max_fragment_length =
  | TWO_9  [@id 1]
  | TWO_10 [@id 2]
  | TWO_11 [@id 3]
  | TWO_12 [@id 4]

let max_fragment_length_to_int = function
  | TWO_9 -> 1
  | TWO_10 -> 2
  | TWO_11 -> 3
  | TWO_12 -> 4
and int_to_max_fragment_length = function
  | 1 -> Some TWO_9
  | 2 -> Some TWO_10
  | 3 -> Some TWO_11
  | 4 -> Some TWO_12
  | _ -> None

(* TLS 1.3 pre-shared key mode (4.2.9) *)
type psk_key_exchange_mode =
  | PSK_KE [@id 0]
  | PSK_KE_DHE [@id 1]

let psk_key_exchange_mode_to_int = function
  | PSK_KE -> 0
  | PSK_KE_DHE -> 1
and int_to_psk_key_exchange_mode = function
  | 0 -> Some PSK_KE
  | 1 -> Some PSK_KE_DHE
  | _ -> None

(* TLS 1.3 4.2.3 *)
type signature_alg =
  | RSA_PKCS1_MD5    [@id 0x0101] (* deprecated, TLS 1.2 only *)
  | RSA_PKCS1_SHA1   [@id 0x0201] (* deprecated, TLS 1.2 only *)
  | RSA_PKCS1_SHA224 [@id 0x0301]
  | RSA_PKCS1_SHA256 [@id 0x0401]
  | RSA_PKCS1_SHA384 [@id 0x0501]
  | RSA_PKCS1_SHA512 [@id 0x0601]
  | ECDSA_SECP256R1_SHA1 [@id 0x0203] (* deprecated, TLS 1.2 only *)
  | ECDSA_SECP256R1_SHA256 [@id 0x0403]
  | ECDSA_SECP384R1_SHA384 [@id 0x0503]
  | ECDSA_SECP521R1_SHA512 [@id 0x0603]
  | RSA_PSS_RSAENC_SHA256 [@id 0x0804]
  | RSA_PSS_RSAENC_SHA384 [@id 0x0805]
  | RSA_PSS_RSAENC_SHA512 [@id 0x0806]
  | ED25519 [@id 0x0807]
  | ED448 [@id 0x0808]
  | RSA_PSS_PSS_SHA256 [@id 0x0809]
  | RSA_PSS_PSS_SHA384 [@id 0x080a]
  | RSA_PSS_PSS_SHA512 [@id 0x080b]
  (* private use 0xFE00 - 0xFFFF *)

let signature_alg_to_int = function
  | RSA_PKCS1_MD5    -> 0x0101 (* deprecated, TLS 1.2 only *)
  | RSA_PKCS1_SHA1   -> 0x0201 (* deprecated, TLS 1.2 only *)
  | RSA_PKCS1_SHA224 -> 0x0301
  | RSA_PKCS1_SHA256 -> 0x0401
  | RSA_PKCS1_SHA384 -> 0x0501
  | RSA_PKCS1_SHA512 -> 0x0601
  | ECDSA_SECP256R1_SHA1 -> 0x0203 (* deprecated, TLS 1.2 only *)
  | ECDSA_SECP256R1_SHA256 -> 0x0403
  | ECDSA_SECP384R1_SHA384 -> 0x0503
  | ECDSA_SECP521R1_SHA512 -> 0x0603
  | RSA_PSS_RSAENC_SHA256 -> 0x0804
  | RSA_PSS_RSAENC_SHA384 -> 0x0805
  | RSA_PSS_RSAENC_SHA512 -> 0x0806
  | ED25519 -> 0x0807
  | ED448 -> 0x0808
  | RSA_PSS_PSS_SHA256 -> 0x0809
  | RSA_PSS_PSS_SHA384 -> 0x080a
  | RSA_PSS_PSS_SHA512 -> 0x080b
  (* private use 0xFE00 - 0xFFFF *)
and int_to_signature_alg = function
  | 0x0101 -> Some RSA_PKCS1_MD5
  | 0x0201 -> Some RSA_PKCS1_SHA1
  | 0x0301 -> Some RSA_PKCS1_SHA224
  | 0x0401 -> Some RSA_PKCS1_SHA256
  | 0x0501 -> Some RSA_PKCS1_SHA384
  | 0x0601 -> Some RSA_PKCS1_SHA512
  | 0x0203 -> Some ECDSA_SECP256R1_SHA1
  | 0x0403 -> Some ECDSA_SECP256R1_SHA256
  | 0x0503 -> Some ECDSA_SECP384R1_SHA384
  | 0x0603 -> Some ECDSA_SECP521R1_SHA512
  | 0x0804 -> Some RSA_PSS_RSAENC_SHA256
  | 0x0805 -> Some RSA_PSS_RSAENC_SHA384
  | 0x0806 -> Some RSA_PSS_RSAENC_SHA512
  | 0x0807 -> Some ED25519
  | 0x0808 -> Some ED448
  | 0x0809 -> Some RSA_PSS_PSS_SHA256
  | 0x080a -> Some RSA_PSS_PSS_SHA384
  | 0x080b -> Some RSA_PSS_PSS_SHA512
  | _ -> None

let to_signature_alg = function
  | `RSA_PKCS1_MD5 -> RSA_PKCS1_MD5
  | `RSA_PKCS1_SHA1 -> RSA_PKCS1_SHA1
  | `RSA_PKCS1_SHA224 -> RSA_PKCS1_SHA224
  | `RSA_PKCS1_SHA256 -> RSA_PKCS1_SHA256
  | `RSA_PKCS1_SHA384 -> RSA_PKCS1_SHA384
  | `RSA_PKCS1_SHA512 -> RSA_PKCS1_SHA512
  | `RSA_PSS_RSAENC_SHA256 -> RSA_PSS_RSAENC_SHA256
  | `RSA_PSS_RSAENC_SHA384 -> RSA_PSS_RSAENC_SHA384
  | `RSA_PSS_RSAENC_SHA512 -> RSA_PSS_RSAENC_SHA512
  | `ECDSA_SECP256R1_SHA1 -> ECDSA_SECP256R1_SHA1
  | `ECDSA_SECP256R1_SHA256 -> ECDSA_SECP256R1_SHA256
  | `ECDSA_SECP384R1_SHA384 -> ECDSA_SECP384R1_SHA384
  | `ECDSA_SECP521R1_SHA512 -> ECDSA_SECP521R1_SHA512
  | `ED25519 -> ED25519

let of_signature_alg = function
  | RSA_PKCS1_MD5 -> Some `RSA_PKCS1_MD5
  | RSA_PKCS1_SHA1 -> Some `RSA_PKCS1_SHA1
  | RSA_PKCS1_SHA224 -> Some `RSA_PKCS1_SHA224
  | RSA_PKCS1_SHA256 -> Some `RSA_PKCS1_SHA256
  | RSA_PKCS1_SHA384 -> Some `RSA_PKCS1_SHA384
  | RSA_PKCS1_SHA512 -> Some `RSA_PKCS1_SHA512
  | RSA_PSS_RSAENC_SHA256 -> Some `RSA_PSS_RSAENC_SHA256
  | RSA_PSS_RSAENC_SHA384 -> Some `RSA_PSS_RSAENC_SHA384
  | RSA_PSS_RSAENC_SHA512 -> Some `RSA_PSS_RSAENC_SHA512
  | ECDSA_SECP256R1_SHA1 -> Some `ECDSA_SECP256R1_SHA1
  | ECDSA_SECP256R1_SHA256 -> Some `ECDSA_SECP256R1_SHA256
  | ECDSA_SECP384R1_SHA384 -> Some `ECDSA_SECP384R1_SHA384
  | ECDSA_SECP521R1_SHA512 -> Some `ECDSA_SECP521R1_SHA512
  | ED25519 -> Some `ED25519
  | _ -> None

(* EC RFC4492*)
type ec_curve_type =
  (* 1 and 2 are deprecated in RFC 8422 *)
  | NAMED_CURVE    [@id 3]

let ec_curve_type_to_int = function
  | NAMED_CURVE -> 3
and int_to_ec_curve_type = function
  | 3 -> Some NAMED_CURVE
  | _ -> None

type named_group =
  (* OBSOLETE_RESERVED 0x0001 - 0x0016 *)
  | SECP256R1 [@id 23]
  | SECP384R1 [@id 24]
  | SECP521R1 [@id 25]
  (* OBSOLETE_RESERVED 0x001A - 0x001C *)
  | X25519          [@id 29] (*RFC8446*)
  | X448            [@id 30] (*RFC8446*)
  | FFDHE2048       [@id 256] (*RFC8446*)
  | FFDHE3072       [@id 257] (*RFC8446*)
  | FFDHE4096       [@id 258] (*RFC8446*)
  | FFDHE6144       [@id 259] (*RFC8446*)
  | FFDHE8192       [@id 260] (*RFC8446*)
  (* FFDHE_PRIVATE_USE 0x01FC - 0x01FF *)
  (* ECDHE_PRIVATE_USE 0xFE00 - 0xFEFF *)
  (* OBSOLETE_RESERVED 0xFF01 - 0xFF02 *)

let named_group_to_int = function
  | SECP256R1 -> 23
  | SECP384R1 -> 24
  | SECP521R1 -> 25
  (* OBSOLETE_RESERVED 0x001A - 0x001C *)
  | X25519          -> 29 (*RFC8446*)
  | X448            -> 30 (*RFC8446*)
  | FFDHE2048       -> 256 (*RFC8446*)
  | FFDHE3072       -> 257 (*RFC8446*)
  | FFDHE4096       -> 258 (*RFC8446*)
  | FFDHE6144       -> 259 (*RFC8446*)
  | FFDHE8192       -> 260 (*RFC8446*)
  (* FFDHE_PRIVATE_USE 0x01FC - 0x01FF *)
  (* ECDHE_PRIVATE_USE 0xFE00 - 0xFEFF *)
  (* OBSOLETE_RESERVED 0xFF01 - 0xFF02 *)
and int_to_named_group = function
  | 23 -> Some SECP256R1
  | 24 -> Some SECP384R1
  | 25 -> Some SECP521R1
  | 29 -> Some X25519
  | 30 -> Some X448
  | 256 -> Some FFDHE2048
  | 257 -> Some FFDHE3072
  | 258 -> Some FFDHE4096
  | 259 -> Some FFDHE6144
  | 260 -> Some FFDHE8192
  | _ -> None

(** enum of all TLS ciphersuites *)
type any_ciphersuite =
  | TLS_RSA_WITH_3DES_EDE_CBC_SHA          [@id 0x000A]
  | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      [@id 0x0016]
  (* from RFC 3268 *)
  | TLS_RSA_WITH_AES_128_CBC_SHA      [@id 0x002F]
  | TLS_DHE_RSA_WITH_AES_128_CBC_SHA  [@id 0x0033]
  | TLS_RSA_WITH_AES_256_CBC_SHA      [@id 0x0035]
  | TLS_DHE_RSA_WITH_AES_256_CBC_SHA  [@id 0x0039]
  (* from RFC 5246 *)
  | TLS_RSA_WITH_AES_128_CBC_SHA256          [@id 0x003C]
  | TLS_RSA_WITH_AES_256_CBC_SHA256          [@id 0x003D]
  | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      [@id 0x0067]
  | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      [@id 0x006B]
  | TLS_RSA_WITH_AES_128_GCM_SHA256          [@id 0x009C] (*RFC5288*)
  | TLS_RSA_WITH_AES_256_GCM_SHA384          [@id 0x009D] (*RFC5288*)
  | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      [@id 0x009E] (*RFC5288*)
  | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      [@id 0x009F] (*RFC5288*)
  | TLS_EMPTY_RENEGOTIATION_INFO_SCSV        [@id 0x00FF] (*RFC5746*)
  | TLS_AES_128_GCM_SHA256                   [@id 0x1301] (*RFC8446*)
  | TLS_AES_256_GCM_SHA384                   [@id 0x1302] (*RFC8446*)
  | TLS_CHACHA20_POLY1305_SHA256             [@id 0x1303] (*RFC8446*)
  | TLS_AES_128_CCM_SHA256                   [@id 0x1304] (*RFC8446*)
  | TLS_FALLBACK_SCSV                        [@id 0x5600] (*draft-ietf-tls-downgrade-scsv*)
  (* from RFC 4492 *)
  | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        [@id 0xC008]
  | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA         [@id 0xC009]
  | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA         [@id 0xC00A]
  | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          [@id 0xC012]
  | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA           [@id 0xC013]
  | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA           [@id 0xC014]
  | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      [@id 0xC023] (*RFC5289*)
  | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384      [@id 0xC024] (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256        [@id 0xC027] (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384        [@id 0xC028] (*RFC5289*)
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      [@id 0xC02B] (*RFC5289*)
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      [@id 0xC02C] (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        [@id 0xC02F] (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        [@id 0xC030] (*RFC5289*)
  | TLS_RSA_WITH_AES_128_CCM                     [@id 0xC09C] (*RFC6655*)
  | TLS_RSA_WITH_AES_256_CCM                     [@id 0xC09D] (*RFC6655*)
  | TLS_DHE_RSA_WITH_AES_128_CCM                 [@id 0xC09E] (*RFC6655*)
  | TLS_DHE_RSA_WITH_AES_256_CCM                 [@id 0xC09F] (*RFC6655*)
  | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256  [@id 0xCCA8] (*RFC7905*)
  | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 [@id 0xCCA9] (*RFC7905*)
  | TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256    [@id 0xCCAA] (*RFC7905*)

let any_ciphersuite_to_int = function
  | TLS_RSA_WITH_3DES_EDE_CBC_SHA          -> 0x000A
  | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      -> 0x0016
  | TLS_RSA_WITH_AES_128_CBC_SHA      -> 0x002F
  | TLS_DHE_RSA_WITH_AES_128_CBC_SHA  -> 0x0033
  | TLS_RSA_WITH_AES_256_CBC_SHA      -> 0x0035
  | TLS_DHE_RSA_WITH_AES_256_CBC_SHA  -> 0x0039
  | TLS_RSA_WITH_AES_128_CBC_SHA256          -> 0x003C
  | TLS_RSA_WITH_AES_256_CBC_SHA256          -> 0x003D
  | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      -> 0x0067
  | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      -> 0x006B
  | TLS_RSA_WITH_AES_128_GCM_SHA256          -> 0x009C (*RFC5288*)
  | TLS_RSA_WITH_AES_256_GCM_SHA384          -> 0x009D (*RFC5288*)
  | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      -> 0x009E (*RFC5288*)
  | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      -> 0x009F (*RFC5288*)
  | TLS_EMPTY_RENEGOTIATION_INFO_SCSV        -> 0x00FF (*RFC5746*)
  | TLS_AES_128_GCM_SHA256                   -> 0x1301 (*RFC8446*)
  | TLS_AES_256_GCM_SHA384                   -> 0x1302 (*RFC8446*)
  | TLS_CHACHA20_POLY1305_SHA256             -> 0x1303 (*RFC8446*)
  | TLS_AES_128_CCM_SHA256                   -> 0x1304 (*RFC8446*)
  | TLS_FALLBACK_SCSV                        -> 0x5600 (*draft-ietf-tls-downgrade-scsv*)
  | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        -> 0xC008
  | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA         -> 0xC009
  | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA         -> 0xC00A
  | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          -> 0xC012
  | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA           -> 0xC013
  | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA           -> 0xC014
  | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      -> 0xC023 (*RFC5289*)
  | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384      -> 0xC024 (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256        -> 0xC027 (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384        -> 0xC028 (*RFC5289*)
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      -> 0xC02B (*RFC5289*)
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      -> 0xC02C (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        -> 0xC02F (*RFC5289*)
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        -> 0xC030 (*RFC5289*)
  | TLS_RSA_WITH_AES_128_CCM                     -> 0xC09C (*RFC6655*)
  | TLS_RSA_WITH_AES_256_CCM                     -> 0xC09D (*RFC6655*)
  | TLS_DHE_RSA_WITH_AES_128_CCM                 -> 0xC09E (*RFC6655*)
  | TLS_DHE_RSA_WITH_AES_256_CCM                 -> 0xC09F (*RFC6655*)
  | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256  -> 0xCCA8 (*RFC7905*)
  | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 -> 0xCCA9 (*RFC7905*)
  | TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256    -> 0xCCAA (*RFC7905*)

and int_to_any_ciphersuite = function
  | 0x000A -> Some TLS_RSA_WITH_3DES_EDE_CBC_SHA
  | 0x0016 -> Some TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | 0x002F -> Some TLS_RSA_WITH_AES_128_CBC_SHA
  | 0x0033 -> Some TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | 0x0035 -> Some TLS_RSA_WITH_AES_256_CBC_SHA
  | 0x0039 -> Some TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | 0x003C -> Some TLS_RSA_WITH_AES_128_CBC_SHA256
  | 0x003D -> Some TLS_RSA_WITH_AES_256_CBC_SHA256
  | 0x0067 -> Some TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | 0x006B -> Some TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | 0x009C -> Some TLS_RSA_WITH_AES_128_GCM_SHA256
  | 0x009D -> Some TLS_RSA_WITH_AES_256_GCM_SHA384
  | 0x009E -> Some TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | 0x009F -> Some TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
  | 0x00FF -> Some TLS_EMPTY_RENEGOTIATION_INFO_SCSV
  | 0x1301 -> Some TLS_AES_128_GCM_SHA256
  | 0x1302 -> Some TLS_AES_256_GCM_SHA384
  | 0x1303 -> Some TLS_CHACHA20_POLY1305_SHA256
  | 0x1304 -> Some TLS_AES_128_CCM_SHA256
  | 0x5600 -> Some TLS_FALLBACK_SCSV
  | 0xC008 -> Some TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
  | 0xC009 -> Some TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  | 0xC00A -> Some TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  | 0xC012 -> Some TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
  | 0xC013 -> Some TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  | 0xC014 -> Some TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  | 0xC023 -> Some TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  | 0xC024 -> Some TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  | 0xC027 -> Some TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  | 0xC028 -> Some TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  | 0xC02B -> Some TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | 0xC02C -> Some TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | 0xC02F -> Some TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | 0xC030 -> Some TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  | 0xC09C -> Some TLS_RSA_WITH_AES_128_CCM
  | 0xC09D -> Some TLS_RSA_WITH_AES_256_CCM
  | 0xC09E -> Some TLS_DHE_RSA_WITH_AES_128_CCM
  | 0xC09F -> Some TLS_DHE_RSA_WITH_AES_256_CCM
  | 0xCCA8 -> Some TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | 0xCCA9 -> Some TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  | 0xCCAA -> Some TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | _ -> None

type key_update_request_type =
  | UPDATE_NOT_REQUESTED [@id 0]
  | UPDATE_REQUESTED [@id 1]

let key_update_request_type_to_int = function
  | UPDATE_NOT_REQUESTED -> 0
  | UPDATE_REQUESTED -> 1
and int_to_key_update_request_type = function
  | 0 -> Some UPDATE_NOT_REQUESTED
  | 1 -> Some UPDATE_REQUESTED
  | _ -> None

let helloretryrequest = Digestif.SHA256.(to_raw_string (digest_string "HelloRetryRequest"))
let downgrade12 = "\x44\x4F\x57\x4E\x47\x52\x44\x01"
let downgrade11 = "\x44\x4F\x57\x4E\x47\x52\x44\x00"
