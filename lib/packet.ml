(** Magic numbers of the TLS protocol. *)

(* HACK: 24 bits type not in cstruct *)
let get_uint24_len buf =
  (Cstruct.BE.get_uint16 buf 0) * 0x100 + (Cstruct.get_uint8 buf 2)

let set_uint24_len buf num =
  Cstruct.BE.set_uint16 buf 0 (num / 0x100);
  Cstruct.set_uint8 buf 2 (num mod 0x100)

(* TLS record content type *)
type content_type =
  | CHANGE_CIPHER_SPEC
  | ALERT
  | HANDSHAKE
  | APPLICATION_DATA
  | HEARTBEAT

let content_type_to_int = function
  | CHANGE_CIPHER_SPEC -> 20
  | ALERT -> 21
  | HANDSHAKE -> 22
  | APPLICATION_DATA -> 23
  | HEARTBEAT -> 24
and int_to_content_type = function
  | 20 -> Some CHANGE_CIPHER_SPEC
  | 21 -> Some ALERT
  | 22 -> Some HANDSHAKE
  | 23 -> Some APPLICATION_DATA
  | 24 -> Some HEARTBEAT
  | _ -> None

let pp_content_type ppf = function
  | CHANGE_CIPHER_SPEC -> Fmt.string ppf "change cipher spec"
  | ALERT -> Fmt.string ppf "alert"
  | HANDSHAKE -> Fmt.string ppf "handshake"
  | APPLICATION_DATA -> Fmt.string ppf "application data"
  | HEARTBEAT -> Fmt.string ppf "heartbeat"

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
  | DECRYPTION_FAILED               [@id 21]  (*RFC5246*)
  | RECORD_OVERFLOW                 [@id 22]  (*RFC5246*)
  | DECOMPRESSION_FAILURE           [@id 30]  (*RFC5246*)
  | HANDSHAKE_FAILURE               [@id 40]  (*RFC5246*)
  | NO_CERTIFICATE_RESERVED         [@id 41]  (*RFC5246*)
  | BAD_CERTIFICATE                 [@id 42]  (*RFC5246*)
  | UNSUPPORTED_CERTIFICATE         [@id 43]  (*RFC5246*)
  | CERTIFICATE_REVOKED             [@id 44]  (*RFC5246*)
  | CERTIFICATE_EXPIRED             [@id 45]  (*RFC5246*)
  | CERTIFICATE_UNKNOWN             [@id 46]  (*RFC5246*)
  | ILLEGAL_PARAMETER               [@id 47]  (*RFC5246*)
  | UNKNOWN_CA                      [@id 48]  (*RFC5246*)
  | ACCESS_DENIED                   [@id 49]  (*RFC5246*)
  | DECODE_ERROR                    [@id 50]  (*RFC5246*)
  | DECRYPT_ERROR                   [@id 51]  (*RFC5246*)
  | EXPORT_RESTRICTION_RESERVED     [@id 60]  (*RFC5246*)
  | PROTOCOL_VERSION                [@id 70]  (*RFC5246*)
  | INSUFFICIENT_SECURITY           [@id 71]  (*RFC5246*)
  | INTERNAL_ERROR                  [@id 80]  (*RFC5246*)
  | INAPPROPRIATE_FALLBACK          [@id 86]  (*draft-ietf-tls-downgrade-scsv*)
  | USER_CANCELED                   [@id 90]  (*RFC5246*)
  | NO_RENEGOTIATION                [@id 100] (*RFC5246*)
  | MISSING_EXTENSION               [@id 109] (*RFC8446*)
  | UNSUPPORTED_EXTENSION           [@id 110] (*RFC5246*)
  | CERTIFICATE_UNOBTAINABLE        [@id 111] (*RFC6066*)
  | UNRECOGNIZED_NAME               [@id 112] (*RFC6066*)
  | BAD_CERTIFICATE_STATUS_RESPONSE [@id 113] (*RFC6066*)
  | BAD_CERTIFICATE_HASH_VALUE      [@id 114] (*RFC6066*)
  | UNKNOWN_PSK_IDENTITY            [@id 115] (*RFC4279*)
  | CERTIFICATE_REQUIRED            [@id 116] (*RFC8446*)
  | NO_APPLICATION_PROTOCOL         [@id 120] (*RFC7301*)

let alert_type_to_string = function
  | CLOSE_NOTIFY -> "close notify"
  | UNEXPECTED_MESSAGE -> "unexpected message"
  | BAD_RECORD_MAC -> "bad record mac"
  | DECRYPTION_FAILED -> "decryption failed"
  | RECORD_OVERFLOW -> "record overflow"
  | DECOMPRESSION_FAILURE -> "decompression failure"
  | HANDSHAKE_FAILURE -> "handshake failure"
  | NO_CERTIFICATE_RESERVED -> "no certificate"
  | BAD_CERTIFICATE -> "bad certificate"
  | UNSUPPORTED_CERTIFICATE -> "unsupported certificate"
  | CERTIFICATE_REVOKED -> "certificate revoked"
  | CERTIFICATE_EXPIRED -> "certificate expired"
  | CERTIFICATE_UNKNOWN -> "certificate unknown"
  | ILLEGAL_PARAMETER -> "illegal parameter"
  | UNKNOWN_CA -> "unknown CA"
  | ACCESS_DENIED -> "access denied"
  | DECODE_ERROR -> "decode error"
  | DECRYPT_ERROR -> "decrypt error"
  | EXPORT_RESTRICTION_RESERVED -> "export restrictions"
  | PROTOCOL_VERSION -> "protocol version"
  | INSUFFICIENT_SECURITY -> "insufficient security"
  | INTERNAL_ERROR -> "internal error"
  | INAPPROPRIATE_FALLBACK -> "inappropriate fallback"
  | USER_CANCELED -> "user canceled"
  | NO_RENEGOTIATION -> "no renegotiation"
  | MISSING_EXTENSION -> "missing extension"
  | UNSUPPORTED_EXTENSION -> "unsupported extension"
  | CERTIFICATE_UNOBTAINABLE -> "certificate unobtainable"
  | UNRECOGNIZED_NAME -> "unrecognized name"
  | BAD_CERTIFICATE_STATUS_RESPONSE -> "bad certificate status response"
  | BAD_CERTIFICATE_HASH_VALUE -> "bad certificate hash value"
  | UNKNOWN_PSK_IDENTITY -> "unknown psk identity"
  | CERTIFICATE_REQUIRED -> "certificate required"
  | NO_APPLICATION_PROTOCOL -> "no application protocol"

let alert_type_to_int = function
  | CLOSE_NOTIFY                    -> 0   (*RFC5246*)
  | UNEXPECTED_MESSAGE              -> 10  (*RFC5246*)
  | BAD_RECORD_MAC                  -> 20  (*RFC5246*)
  | DECRYPTION_FAILED               -> 21  (*RFC5246*)
  | RECORD_OVERFLOW                 -> 22  (*RFC5246*)
  | DECOMPRESSION_FAILURE           -> 30  (*RFC5246*)
  | HANDSHAKE_FAILURE               -> 40  (*RFC5246*)
  | NO_CERTIFICATE_RESERVED         -> 41  (*RFC5246*)
  | BAD_CERTIFICATE                 -> 42  (*RFC5246*)
  | UNSUPPORTED_CERTIFICATE         -> 43  (*RFC5246*)
  | CERTIFICATE_REVOKED             -> 44  (*RFC5246*)
  | CERTIFICATE_EXPIRED             -> 45  (*RFC5246*)
  | CERTIFICATE_UNKNOWN             -> 46  (*RFC5246*)
  | ILLEGAL_PARAMETER               -> 47  (*RFC5246*)
  | UNKNOWN_CA                      -> 48  (*RFC5246*)
  | ACCESS_DENIED                   -> 49  (*RFC5246*)
  | DECODE_ERROR                    -> 50  (*RFC5246*)
  | DECRYPT_ERROR                   -> 51  (*RFC5246*)
  | EXPORT_RESTRICTION_RESERVED     -> 60  (*RFC5246*)
  | PROTOCOL_VERSION                -> 70  (*RFC5246*)
  | INSUFFICIENT_SECURITY           -> 71  (*RFC5246*)
  | INTERNAL_ERROR                  -> 80  (*RFC5246*)
  | INAPPROPRIATE_FALLBACK          -> 86  (*draft-ietf-tls-downgrade-scsv*)
  | USER_CANCELED                   -> 90  (*RFC5246*)
  | NO_RENEGOTIATION                -> 100 (*RFC5246*)
  | MISSING_EXTENSION               -> 109 (*RFC8446*)
  | UNSUPPORTED_EXTENSION           -> 110 (*RFC5246*)
  | CERTIFICATE_UNOBTAINABLE        -> 111 (*RFC6066*)
  | UNRECOGNIZED_NAME               -> 112 (*RFC6066*)
  | BAD_CERTIFICATE_STATUS_RESPONSE -> 113 (*RFC6066*)
  | BAD_CERTIFICATE_HASH_VALUE      -> 114 (*RFC6066*)
  | UNKNOWN_PSK_IDENTITY            -> 115 (*RFC4279*)
  | CERTIFICATE_REQUIRED            -> 116 (*RFC8446*)
  | NO_APPLICATION_PROTOCOL         -> 120 (*RFC7301*)
and int_to_alert_type = function
  | 0 -> Some CLOSE_NOTIFY
  | 10 -> Some UNEXPECTED_MESSAGE
  | 20 -> Some BAD_RECORD_MAC
  | 21 -> Some DECRYPTION_FAILED
  | 22 -> Some RECORD_OVERFLOW
  | 30 -> Some DECOMPRESSION_FAILURE
  | 40 -> Some HANDSHAKE_FAILURE
  | 41 -> Some NO_CERTIFICATE_RESERVED
  | 42 -> Some BAD_CERTIFICATE
  | 43 -> Some UNSUPPORTED_CERTIFICATE
  | 44 -> Some CERTIFICATE_REVOKED
  | 45 -> Some CERTIFICATE_EXPIRED
  | 46 -> Some CERTIFICATE_UNKNOWN
  | 47 -> Some ILLEGAL_PARAMETER
  | 48 -> Some UNKNOWN_CA
  | 49 -> Some ACCESS_DENIED
  | 50 -> Some DECODE_ERROR
  | 51 -> Some DECRYPT_ERROR
  | 60 -> Some EXPORT_RESTRICTION_RESERVED
  | 70 -> Some PROTOCOL_VERSION
  | 71 -> Some INSUFFICIENT_SECURITY
  | 80 -> Some INTERNAL_ERROR
  | 86 -> Some INAPPROPRIATE_FALLBACK
  | 90 -> Some USER_CANCELED
  | 100 -> Some NO_RENEGOTIATION
  | 109 -> Some MISSING_EXTENSION
  | 110 -> Some UNSUPPORTED_EXTENSION
  | 111 -> Some CERTIFICATE_UNOBTAINABLE
  | 112 -> Some UNRECOGNIZED_NAME
  | 113 -> Some BAD_CERTIFICATE_STATUS_RESPONSE
  | 114 -> Some BAD_CERTIFICATE_HASH_VALUE
  | 115 -> Some UNKNOWN_PSK_IDENTITY
  | 116 -> Some CERTIFICATE_REQUIRED
  | 120 -> Some NO_APPLICATION_PROTOCOL
  | _ -> None

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
  | DSS_SIGN                  [@id 2]  (*RFC5246*)
  | RSA_FIXED_DH              [@id 3]  (*RFC5246*)
  | DSS_FIXED_DH              [@id 4]  (*RFC5246*)
  | RSA_EPHEMERAL_DH_RESERVED [@id 5]  (*RFC5246*)
  | DSS_EPHEMERAL_DH_RESERVED [@id 6]  (*RFC5246*)
  | FORTEZZA_DMS_RESERVED     [@id 20] (*RFC5246*)
  | ECDSA_SIGN                [@id 64] (*RFC4492*)
  | RSA_FIXED_ECDH            [@id 65] (*RFC4492*)
  | ECDSA_FIXED_ECDH          [@id 66] (*RFC4492*)

let client_certificate_type_to_int = function
  | RSA_SIGN                  -> 1  (*RFC5246*)
  | DSS_SIGN                  -> 2  (*RFC5246*)
  | RSA_FIXED_DH              -> 3  (*RFC5246*)
  | DSS_FIXED_DH              -> 4  (*RFC5246*)
  | RSA_EPHEMERAL_DH_RESERVED -> 5  (*RFC5246*)
  | DSS_EPHEMERAL_DH_RESERVED -> 6  (*RFC5246*)
  | FORTEZZA_DMS_RESERVED     -> 20 (*RFC5246*)
  | ECDSA_SIGN                -> 64 (*RFC4492*)
  | RSA_FIXED_ECDH            -> 65 (*RFC4492*)
  | ECDSA_FIXED_ECDH          -> 66 (*RFC4492*)
and int_to_client_certificate_type = function
  | 1 -> Some RSA_SIGN
  | 2 -> Some DSS_SIGN
  | 3 -> Some RSA_FIXED_DH
  | 4 -> Some DSS_FIXED_DH
  | 5 -> Some RSA_EPHEMERAL_DH_RESERVED
  | 6 -> Some DSS_EPHEMERAL_DH_RESERVED
  | 20 -> Some FORTEZZA_DMS_RESERVED
  | 64 -> Some ECDSA_SIGN
  | 65 -> Some RSA_FIXED_ECDH
  | 66 -> Some ECDSA_FIXED_ECDH
  | _ -> None

(* TLS compression methods, used in hello packets *)
type compression_method =
  | NULL    [@id 0]
  | DEFLATE [@id 1]
  | LZS     [@id 64]

let compression_method_to_int = function
  | NULL -> 0
  | DEFLATE -> 1
  | LZS -> 64
and int_to_compression_method = function
  | 0 -> Some NULL
  | 1 -> Some DEFLATE
  | 64 -> Some LZS
  | _ -> None

(* TLS extensions in hello packets from RFC 6066, formerly RFC 4366 *)
type extension_type =
  | SERVER_NAME                            [@id 0]
  | MAX_FRAGMENT_LENGTH                    [@id 1]
  | CLIENT_CERTIFICATE_URL                 [@id 2]
  | TRUSTED_CA_KEYS                        [@id 3]
  | TRUNCATED_HMAC                         [@id 4]
  | STATUS_REQUEST                         [@id 5]
  | USER_MAPPING                           [@id 6]  (*RFC4681*)
  | CLIENT_AUTHZ                           [@id 7]  (*RFC5878*)
  | SERVER_AUTHZ                           [@id 8]  (*RFC5878*)
  | CERT_TYPE                              [@id 9]  (*RFC6091*)
  | SUPPORTED_GROUPS                       [@id 10] (*RFC4492, RFC8446*)
  | EC_POINT_FORMATS                       [@id 11] (*RFC4492*)
  | SRP                                    [@id 12] (*RFC5054*)
  | SIGNATURE_ALGORITHMS                   [@id 13] (*RFC5246*)
  | USE_SRTP                               [@id 14] (*RFC5764*)
  | HEARTBEAT                              [@id 15] (*RFC6520*)
  | APPLICATION_LAYER_PROTOCOL_NEGOTIATION [@id 16] (*RFC7301*)
  | STATUS_REQUEST_V2                      [@id 17] (*RFC6961*)
  | SIGNED_CERTIFICATE_TIMESTAMP           [@id 18] (*RFC6962*)
  | CLIENT_CERTIFICATE_TYPE                [@id 19] (*RFC7250*)
  | SERVER_CERTIFICATE_TYPE                [@id 20] (*RFC7250*)
  | PADDING                                [@id 21] (*RFC7685*)
  | ENCRYPT_THEN_MAC                       [@id 22] (*RFC7366*)
  | EXTENDED_MASTER_SECRET                 [@id 23] (*RFC7627*)
  | TOKEN_BINDING                          [@id 24] (*RFC8472*)
  | CACHED_INFO                            [@id 25] (*RFC7924*)
  | TLS_LTS                                [@id 26] (*draft-gutmann-tls-lts*)
  | COMPRESSED_CERTIFICATE                 [@id 27] (*draft-ietf-tls-certificate-compression*)
  | RECORD_SIZE_LIMIT                      [@id 28] (*RFC8449*)
  | PWD_PROTECT                            [@id 29] (*RFC-harkins-tls-dragonfly-03*)
  | PWD_CLEAR                              [@id 30] (*RFC-harkins-tls-dragonfly-03*)
  | PASSWORD_SALT                          [@id 31] (*RFC-harkins-tls-dragonfly-03*)
  | SESSION_TICKET                         [@id 35] (*RFC4507*)
  | PRE_SHARED_KEY                         [@id 41] (*RFC8446*)
  | EARLY_DATA                             [@id 42] (*RFC8446*)
  | SUPPORTED_VERSIONS                     [@id 43] (*RFC8446*)
  | COOKIE                                 [@id 44] (*RFC8446*)
  | PSK_KEY_EXCHANGE_MODES                 [@id 45] (*RFC8446*)
  | CERTIFICATE_AUTHORITIES                [@id 47] (*RFC8446*)
  | OID_FILTERS                            [@id 48] (*RFC8446*)
  | POST_HANDSHAKE_AUTH                    [@id 49] (*RFC8446*)
  | SIGNATURE_ALGORITHMS_CERT              [@id 50] (*RFC8446*)
  | KEY_SHARE                              [@id 51] (*RFC8446*)
  | RENEGOTIATION_INFO                     [@id 0xFF01] (*RFC5746*)
  | DRAFT_SUPPORT                          [@id 0xFF02] (*draft*)

let extension_type_to_int = function
  | SERVER_NAME                            -> 0
  | MAX_FRAGMENT_LENGTH                    -> 1
  | CLIENT_CERTIFICATE_URL                 -> 2
  | TRUSTED_CA_KEYS                        -> 3
  | TRUNCATED_HMAC                         -> 4
  | STATUS_REQUEST                         -> 5
  | USER_MAPPING                           -> 6  (*RFC4681*)
  | CLIENT_AUTHZ                           -> 7  (*RFC5878*)
  | SERVER_AUTHZ                           -> 8  (*RFC5878*)
  | CERT_TYPE                              -> 9  (*RFC6091*)
  | SUPPORTED_GROUPS                       -> 10 (*RFC4492, RFC8446*)
  | EC_POINT_FORMATS                       -> 11 (*RFC4492*)
  | SRP                                    -> 12 (*RFC5054*)
  | SIGNATURE_ALGORITHMS                   -> 13 (*RFC5246*)
  | USE_SRTP                               -> 14 (*RFC5764*)
  | HEARTBEAT                              -> 15 (*RFC6520*)
  | APPLICATION_LAYER_PROTOCOL_NEGOTIATION -> 16 (*RFC7301*)
  | STATUS_REQUEST_V2                      -> 17 (*RFC6961*)
  | SIGNED_CERTIFICATE_TIMESTAMP           -> 18 (*RFC6962*)
  | CLIENT_CERTIFICATE_TYPE                -> 19 (*RFC7250*)
  | SERVER_CERTIFICATE_TYPE                -> 20 (*RFC7250*)
  | PADDING                                -> 21 (*RFC7685*)
  | ENCRYPT_THEN_MAC                       -> 22 (*RFC7366*)
  | EXTENDED_MASTER_SECRET                 -> 23 (*RFC7627*)
  | TOKEN_BINDING                          -> 24 (*RFC8472*)
  | CACHED_INFO                            -> 25 (*RFC7924*)
  | TLS_LTS                                -> 26 (*draft-gutmann-tls-lts*)
  | COMPRESSED_CERTIFICATE                 -> 27 (*draft-ietf-tls-certificate-compression*)
  | RECORD_SIZE_LIMIT                      -> 28 (*RFC8449*)
  | PWD_PROTECT                            -> 29 (*RFC-harkins-tls-dragonfly-03*)
  | PWD_CLEAR                              -> 30 (*RFC-harkins-tls-dragonfly-03*)
  | PASSWORD_SALT                          -> 31 (*RFC-harkins-tls-dragonfly-03*)
  | SESSION_TICKET                         -> 35 (*RFC4507*)
  | PRE_SHARED_KEY                         -> 41 (*RFC8446*)
  | EARLY_DATA                             -> 42 (*RFC8446*)
  | SUPPORTED_VERSIONS                     -> 43 (*RFC8446*)
  | COOKIE                                 -> 44 (*RFC8446*)
  | PSK_KEY_EXCHANGE_MODES                 -> 45 (*RFC8446*)
  | CERTIFICATE_AUTHORITIES                -> 47 (*RFC8446*)
  | OID_FILTERS                            -> 48 (*RFC8446*)
  | POST_HANDSHAKE_AUTH                    -> 49 (*RFC8446*)
  | SIGNATURE_ALGORITHMS_CERT              -> 50 (*RFC8446*)
  | KEY_SHARE                              -> 51 (*RFC8446*)
  | RENEGOTIATION_INFO                     -> 0xFF01 (*RFC5746*)
  | DRAFT_SUPPORT                          -> 0xFF02 (*draft*)
and int_to_extension_type = function
  | 0 -> Some SERVER_NAME
  | 1 -> Some MAX_FRAGMENT_LENGTH
  | 2 -> Some CLIENT_CERTIFICATE_URL
  | 3 -> Some TRUSTED_CA_KEYS
  | 4 -> Some TRUNCATED_HMAC
  | 5 -> Some STATUS_REQUEST
  | 6 -> Some USER_MAPPING
  | 7 -> Some CLIENT_AUTHZ
  | 8 -> Some SERVER_AUTHZ
  | 9 -> Some CERT_TYPE
  | 10 -> Some SUPPORTED_GROUPS
  | 11 -> Some EC_POINT_FORMATS
  | 12 -> Some SRP
  | 13 -> Some SIGNATURE_ALGORITHMS
  | 14 -> Some USE_SRTP
  | 15 -> Some HEARTBEAT
  | 16 -> Some APPLICATION_LAYER_PROTOCOL_NEGOTIATION
  | 17 -> Some STATUS_REQUEST_V2
  | 18 -> Some SIGNED_CERTIFICATE_TIMESTAMP
  | 19 -> Some CLIENT_CERTIFICATE_TYPE
  | 20 -> Some SERVER_CERTIFICATE_TYPE
  | 21 -> Some PADDING
  | 22 -> Some ENCRYPT_THEN_MAC
  | 23 -> Some EXTENDED_MASTER_SECRET
  | 24 -> Some TOKEN_BINDING
  | 25 -> Some CACHED_INFO
  | 26 -> Some TLS_LTS
  | 27 -> Some COMPRESSED_CERTIFICATE
  | 28 -> Some RECORD_SIZE_LIMIT
  | 29 -> Some PWD_PROTECT
  | 30 -> Some PWD_CLEAR
  | 31 -> Some PASSWORD_SALT
  | 35 -> Some SESSION_TICKET
  | 41 -> Some PRE_SHARED_KEY
  | 42 -> Some EARLY_DATA
  | 43 -> Some SUPPORTED_VERSIONS
  | 44 -> Some COOKIE
  | 45 -> Some PSK_KEY_EXCHANGE_MODES
  | 47 -> Some CERTIFICATE_AUTHORITIES
  | 48 -> Some OID_FILTERS
  | 49 -> Some POST_HANDSHAKE_AUTH
  | 50 -> Some SIGNATURE_ALGORITHMS_CERT
  | 51 -> Some KEY_SHARE
  | 0xFF01 -> Some RENEGOTIATION_INFO
  | 0xFF02 -> Some DRAFT_SUPPORT
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

let helloretryrequest = Mirage_crypto.Hash.digest `SHA256 (Cstruct.of_string "HelloRetryRequest")
let downgrade12 = Cstruct.of_hex "44 4F 57 4E 47 52 44 01"
let downgrade11 = Cstruct.of_hex "44 4F 57 4E 47 52 44 00"
