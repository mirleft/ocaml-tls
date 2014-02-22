open Cstruct

(* HACK: 24 bits type not in cstruct *)
let get_uint24_len buf =
  (Cstruct.BE.get_uint16 buf 0) * 0x100 + (Cstruct.get_uint8 buf 2)

let set_uint24_len buf num =
  Cstruct.BE.set_uint16 buf 0 (num / 0x100);
  Cstruct.set_uint8 buf 2 (num mod 0x100)

(* TLS Record Header *)
cstruct tls_h {
  uint8_t  content_type;
  uint8_t  major_version;
  uint8_t  minor_version;
  uint16_t length
} as big_endian

(* TLS Client and Server hello handshake header *)
cstruct c_hello {
  uint8_t major_version;
  uint8_t minor_version;
  uint8_t  random[32];
} as big_endian

(* TLS record content type *)
cenum content_type {
  CHANGE_CIPHER_SPEC = 20;
  ALERT              = 21;
  HANDSHAKE          = 22;
  APPLICATION_DATA   = 23;
  HEARTBEAT          = 24
} as uint8_t

(* TLS alert level *)
cenum alert_level {
  WARNING = 1;
  FATAL = 2
} as uint8_t

(* TLS alert types *)
cenum alert_type {
  CLOSE_NOTIFY = 0; (*RFC5246*)
  UNEXPECTED_MESSAGE = 10; (*RFC5246*)
  BAD_RECORD_MAC = 20; (*RFC5246*)
  DECRYPTION_FAILED = 21; (*RFC5246*)
  RECORD_OVERFLOW = 22; (*RFC5246*)
  DECOMPRESSION_FAILURE = 30; (*RFC5246*)
  HANDSHAKE_FAILURE = 40; (*RFC5246*)
  NO_CERTIFICATE_RESERVED = 41; (*RFC5246*)
  BAD_CERTIFICATE = 42; (*RFC5246*)
  UNSUPPORTED_CERTIFICATE = 43; (*RFC5246*)
  CERTIFICATE_REVOKED = 44; (*RFC5246*)
  CERTIFICATE_EXPIRED = 45; (*RFC5246*)
  CERTIFICATE_UNKNOWN = 46; (*RFC5246*)
  ILLEGAL_PARAMETER = 47; (*RFC5246*)
  UNKNOWN_CA = 48; (*RFC5246*)
  ACCESS_DENIED = 49; (*RFC5246*)
  DECODE_ERROR = 50; (*RFC5246*)
  DECRYPT_ERROR = 51; (*RFC5246*)
  EXPORT_RESTRICTION_RESERVED = 60; (*RFC5246*)
  PROTOCOL_VERSION = 70; (*RFC5246*)
  INSUFFICIENT_SECURITY = 71; (*RFC5246*)
  INTERNAL_ERROR = 80; (*RFC5246*)
  USER_CANCELED = 90; (*RFC5246*)
  NO_RENEGOTIATION = 100; (*RFC5246*)
  UNSUPPORTED_EXTENSION = 110; (*RFC5246*)
  CERTIFICATE_UNOBTAINABLE = 111; (*RFC6066*)
  UNRECOGNIZED_NAME = 112; (*RFC6066*)
  BAD_CERTIFICATE_STATUS_RESPONSE = 113; (*RFC6066*)
  BAD_CERTIFICATE_HASH_VALUE = 114; (*RFC6066*)
  UNKNOWN_PSK_IDENTITY = 115; (*RFC4279*)
} as uint8_t

(* TLS handshake type *)
cenum handshake_type {
  HELLO_REQUEST        = 0;
  CLIENT_HELLO         = 1;
  SERVER_HELLO         = 2;
  HELLO_VERIFY_REQUEST = 3; (*RFC6347*)
  NEWSESSIONTICKET     = 4; (*RFC4507*)
  CERTIFICATE          = 11;
  SERVER_KEY_EXCHANGE  = 12;
  CERTIFICATE_REQUEST  = 13;
  SERVER_HELLO_DONE    = 14;
  CERTIFICATE_VERIFY   = 15;
  CLIENT_KEY_EXCHANGE  = 16;
  FINISHED             = 20;
  (* from RFC 4366 *)
  CERTIFICATE_URL      = 21;
  CERTIFICATE_STATUS   = 22;
  SUPPLEMENTAL_DATA    = 23; (*RFC4680*)
} as uint8_t

(* TLS certificate types *)
cenum client_certificate_type {
  RSA_SIGN = 1; (*RFC5246*)
  DSS_SIGN = 2; (*RFC5246*)
  RSA_FIXED_DH = 3; (*RFC5246*)
  DSS_FIXED_DH = 4; (*RFC5246*)
  RSA_EPHEMERAL_DH_RESERVED = 5; (*RFC5246*)
  DSS_EPHEMERAL_DH_RESERVED = 6; (*RFC5246*)
  FORTEZZA_DMS_RESERVED = 20; (*RFC5246*)
  ECDSA_SIGN = 64; (*RFC4492*)
  RSA_FIXED_ECDH = 65; (*RFC4492*)
  ECDSA_FIXED_ECDH = 66; (*RFC4492*)
} as uint8_t

(* TLS compression methods, used in hello packets *)
cenum compression_method {
  NULL    = 0  ;
  DEFLATE = 1  ;
  LZS     = 64 ;
} as uint8_t

(* TLS extensions in hello packets from RFC 4366 *)
cenum extension_type {
  SERVER_NAME = 0;
  MAX_FRAGMENT_LENGTH = 1;
  CLIENT_CERTIFICATE_URL = 2;
  TRUSTED_CA_KEYS =3;
  TRUNCATED_HMAC = 4;
  STATUS_REQUEST = 5;
  USER_MAPPING = 6; (*RFC4681*)
  CLIENT_AUTHZ = 7; (*RFC5878*)
  SERVER_AUTHZ = 8; (*RFC5878*)
  CERT_TYPE = 9; (*RFC6091*)
  (* from RFC 4492 *)
  ELLIPTIC_CURVES = 0x000A;
  EC_POINT_FORMATS = 0x000B;
  SRP = 12; (*RFC5054*)
  SIGNATURE_ALGORITHMS = 13; (*RFC5246*)
  USE_SRP = 14; (*RFC5764*)
  HEARTBEAT = 15; (*RFC6520*)
  APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16; (*draft-friedl-tls-applayerprotoneg*)
  STATUS_REQUEST_V2 = 17; (*RFC6961*)
  SIGNED_CERTIFICATE_TIMESTAMP = 18; (*RFC6962*)
  CLIENT_CERTIFICATE_TYPE = 19; (*RFC-ietf-tls-oob-pubkey-11*)
  SERVER_CERTIFICATE_TYPE = 20; (*RFC-ietf-tls-oob-pubkey-11*)
  SESSIONTICKET_TLS = 35; (*RFC4507*)
  RENEGOTIATION_INFO = 0xFF01; (*RFC5746*)
} as uint16_t

(* TLS maximum fragment length *)
cenum max_fragment_length {
  TWO_9 = 1;
  TWO_10 = 2;
  TWO_11 = 3;
  TWO_12 = 4
} as uint8_t

(* RFC 5246 *)
cenum signature_algorithm_type {
  ANONYMOUS = 0;
  RSA = 1;
  DSA = 2;
  ECDSA = 3;
} as uint8_t

cenum hash_algorithm_type {
  NONE = 0;
  MD5 = 1;
  SHA1 = 2;
  SHA224 = 3;
  SHA256 = 4;
  SHA384 = 5;
  SHA512 = 6;
} as uint8_t

(* EC RFC4492*)
cenum ec_curve_type {
  EXPLICIT_PRIME = 1;
  EXPLICIT_CHAR2 = 2;
  NAMED_CURVE = 3
} as uint8_t

cenum named_curve_type {
  SECT163K1 = 1;
  SECT163R1 = 2;
  SECT163R2 = 3;
  SECT193R1 = 4;
  SECT193R2 = 5;
  SECT233K1 = 6;
  SECT233R1 = 7;
  SECT239K1 = 8;
  SECT283K1 = 9;
  SECT283R1 = 10;
  SECT409K1 = 11;
  SECT409R1 = 12;
  SECT571K1 = 13;
  SECT571R1 = 14;
  SECP160K1 = 15;
  SECP160R1 = 16;
  SECP160R2 = 17;
  SECP192K1 = 18;
  SECP192R1 = 19;
  SECP224K1 = 20;
  SECP224R1 = 21;
  SECP256K1 = 22;
  SECP256R1 = 23;
  SECP384R1 = 24;
  SECP521R1 = 25;
  (*RFC7027*)
  BRAINPOOLP256R1 = 26;
  BRAINPOOLP384R1 = 27;
  BRAINPOOLP512R1 = 28;
  (* reserved (0xFE00..0xFEFF), *)
  ARBITRARY_EXPLICIT_PRIME_CURVES = 0xFF01;
  ARBITRARY_EXPLICIT_CHAR2_CURVES = 0xFF02
} as uint16_t

cenum ec_point_format {
  UNCOMPRESSED = 0;
  ANSIX962_COMPRESSED_PRIME = 1;
  ANSIX962_COMPRESSED_CHAR2 = 2;
  (* reserved 248..255 *)
} as uint8_t

cenum ec_basis_type {
  TRINOMIAL = 0;
  PENTANOMIAL = 1
} as uint8_t
