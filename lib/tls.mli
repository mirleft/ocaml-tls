(** Transport layer security

    [TLS] is an implementation of
    {{:https://en.wikipedia.org/wiki/Transport_Layer_Security}transport layer
    security} in OCaml.  TLS is a widely used security protocol which
    establishes an end-to-end secure channel (with optional (mutual)
    authentication) between two endpoints.  It uses TCP/IP as transport.  This
    library supports all three versions of TLS:
    {{:https://tools.ietf.org/html/rfc5246}1.2, RFC5246},
    {{:https://tools.ietf.org/html/rfc4346}1.1, RFC4346}, and
    {{:https://tools.ietf.org/html/rfc2246}1.0, RFC2246}.  SSL, the previous
    protocol definition, is not supported.

    TLS is algorithmically agile: protocol version, key exchange algorithm,
    symmetric cipher, and message authentication code are negotiated upon
    connection.

    This library implements several extensions of TLS,
    {{:https://tools.ietf.org/html/rfc3268}AES ciphers},
    {{:https://tools.ietf.org/html/rfc4366}TLS extensions} (such as server name
    indication, SNI), {{:https://tools.ietf.org/html/rfc5746}Renegotiation
    extension}, {{:https://tools.ietf.org/html/rfc7627}Session Hash and Extended
    Master Secret Extension}.

    This library does not contain insecure cipher suites (such as single DES,
    export ciphers, ...).  It does not expose the server time in the server
    random, requires secure renegotiation.

    This library consists of a core, implemented in a purely functional matter
    ({!Engine}, this module), and effectful parts: {!Tls_lwt} and
    {!Tls_mirage}. *)

open Sexplib

module Tracing : sig
  val active : hook:(Sexp.t -> unit) -> (unit -> 'a) -> 'a

  val sexp   : tag:string -> Sexp.t Lazy.t -> unit
  val sexps  : tag:string -> Sexp.t Lazy.t list -> unit

  val sexpf  : tag:string -> f:('a -> Sexp.t) -> 'a -> unit
  val sexpfs : tag:string -> f:('a -> Sexp.t) -> 'a list -> unit

  val cs     : tag:string -> Cstruct.t -> unit
  val css    : tag:string -> Cstruct.t list -> unit
end

module Packet : sig
  val get_uint24_len : Cstruct.t -> int
  val set_uint24_len : Cstruct.t -> int -> unit

  (* TLS record content type *)
  [%%cenum
  type content_type =
    | CHANGE_CIPHER_SPEC [@id 20]
    | ALERT              [@id 21]
    | HANDSHAKE          [@id 22]
    | APPLICATION_DATA   [@id 23]
    | HEARTBEAT          [@id 24]
  [@@uint8_t] [@@sexp]]

  (* TLS alert level *)
  [%%cenum
  type alert_level =
    | WARNING [@id 1]
    | FATAL   [@id 2]
  [@@uint8_t] [@@sexp]]

  (* TLS alert types *)
  [%%cenum
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
    | UNSUPPORTED_EXTENSION           [@id 110] (*RFC5246*)
    | CERTIFICATE_UNOBTAINABLE        [@id 111] (*RFC6066*)
    | UNRECOGNIZED_NAME               [@id 112] (*RFC6066*)
    | BAD_CERTIFICATE_STATUS_RESPONSE [@id 113] (*RFC6066*)
    | BAD_CERTIFICATE_HASH_VALUE      [@id 114] (*RFC6066*)
    | UNKNOWN_PSK_IDENTITY            [@id 115] (*RFC4279*)
  [@@uint8_t] [@@sexp]]

  (* TLS handshake type *)
  [%%cenum
  type handshake_type =
    | HELLO_REQUEST        [@id 0]
    | CLIENT_HELLO         [@id 1]
    | SERVER_HELLO         [@id 2]
    | HELLO_VERIFY_REQUEST [@id 3] (*RFC6347*)
    | NEWSESSIONTICKET     [@id 4] (*RFC4507*)
    | CERTIFICATE          [@id 11]
    | SERVER_KEY_EXCHANGE  [@id 12]
    | CERTIFICATE_REQUEST  [@id 13]
    | SERVER_HELLO_DONE    [@id 14]
    | CERTIFICATE_VERIFY   [@id 15]
    | CLIENT_KEY_EXCHANGE  [@id 16]
    | FINISHED             [@id 20]
    (* from RFC 4366 *)
    | CERTIFICATE_URL      [@id 21]
    | CERTIFICATE_STATUS   [@id 22]
    | SUPPLEMENTAL_DATA    [@id 23] (*RFC4680*)
  [@@uint8_t] [@@sexp]]

  (* TLS certificate types *)
  [%%cenum
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
  [@@uint8_t] [@@sexp]]

  (* TLS compression methods, used in hello packets *)
  [%%cenum
  type compression_method =
    | NULL    [@id 0]
    | DEFLATE [@id 1]
    | LZS     [@id 64]
  [@@uint8_t] [@@sexp]]

  (* TLS extensions in hello packets from RFC 6066, formerly RFC 4366 *)
  [%%cenum
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
    | ELLIPTIC_CURVES                        [@id 10] (*RFC4492*)
    | EC_POINT_FORMATS                       [@id 11] (*RFC4492*)
    | SRP                                    [@id 12] (*RFC5054*)
    | SIGNATURE_ALGORITHMS                   [@id 13] (*RFC5246*)
    | USE_SRP                                [@id 14] (*RFC5764*)
    | HEARTBEAT                              [@id 15] (*RFC6520*)
    | APPLICATION_LAYER_PROTOCOL_NEGOTIATION [@id 16] (*RFC7301*)
    | STATUS_REQUEST_V2                      [@id 17] (*RFC6961*)
    | SIGNED_CERTIFICATE_TIMESTAMP           [@id 18] (*RFC6962*)
    | CLIENT_CERTIFICATE_TYPE                [@id 19] (*RFC7250*)
    | SERVER_CERTIFICATE_TYPE                [@id 20] (*RFC7250*)
    | PADDING                                [@id 21] (*draft-ietf-tls-padding*)
    | ENCRYPT_THEN_MAC                       [@id 22] (*RFC7366*)
    | EXTENDED_MASTER_SECRET                 [@id 23] (*draft-ietf-tls-session-hash*)
    | SESSIONTICKET_TLS                      [@id 35] (*RFC4507*)
    | RENEGOTIATION_INFO                     [@id 0xFF01] (*RFC5746*)
  [@@uint16_t] [@@sexp]]

  (* TLS maximum fragment length *)
  [%%cenum
  type max_fragment_length =
    | TWO_9  [@id 1]
    | TWO_10 [@id 2]
    | TWO_11 [@id 3]
    | TWO_12 [@id 4]
  [@@uint8_t] [@@sexp]]

  (* RFC 5246 *)
  [%%cenum
  type signature_algorithm_type =
    | ANONYMOUS [@id 0]
    | RSA       [@id 1]
    | DSA       [@id 2]
    | ECDSA     [@id 3]
  [@@uint8_t] [@@sexp]]

  [%%cenum
  type hash_algorithm =
    | NULL      [@id 0]
    | MD5       [@id 1]
    | SHA       [@id 2]
    | SHA224    [@id 3]
    | SHA256    [@id 4]
    | SHA384    [@id 5]
    | SHA512    [@id 6]
  [@@uint8_t] [@@sexp]]

  val hash_algorithm_of_tag : Nocrypto.Hash.hash -> hash_algorithm
  val tag_of_hash_algorithm : hash_algorithm -> Nocrypto.Hash.hash option

  (* EC RFC4492*)
  [%%cenum
  type ec_curve_type =
    | EXPLICIT_PRIME [@id 1]
    | EXPLICIT_CHAR2 [@id 2]
    | NAMED_CURVE    [@id 3]
  [@@uint8_t] [@@sexp]]

  [%%cenum
  type named_curve_type =
    | SECT163K1 [@id 1]
    | SECT163R1 [@id 2]
    | SECT163R2 [@id 3]
    | SECT193R1 [@id 4]
    | SECT193R2 [@id 5]
    | SECT233K1 [@id 6]
    | SECT233R1 [@id 7]
    | SECT239K1 [@id 8]
    | SECT283K1 [@id 9]
    | SECT283R1 [@id 10]
    | SECT409K1 [@id 11]
    | SECT409R1 [@id 12]
    | SECT571K1 [@id 13]
    | SECT571R1 [@id 14]
    | SECP160K1 [@id 15]
    | SECP160R1 [@id 16]
    | SECP160R2 [@id 17]
    | SECP192K1 [@id 18]
    | SECP192R1 [@id 19]
    | SECP224K1 [@id 20]
    | SECP224R1 [@id 21]
    | SECP256K1 [@id 22]
    | SECP256R1 [@id 23]
    | SECP384R1 [@id 24]
    | SECP521R1 [@id 25]
    (*RFC7027*)
    | BRAINPOOLP256R1 [@id 26]
    | BRAINPOOLP384R1 [@id 27]
    | BRAINPOOLP512R1 [@id 28]
    (* reserved (0xFE00..0xFEFF), *)
    | ARBITRARY_EXPLICIT_PRIME_CURVES [@id 0xFF01]
    | ARBITRARY_EXPLICIT_CHAR2_CURVES [@id 0xFF02]
  [@@uint16_t] [@@sexp]]

  [%%cenum
  type ec_point_format =
    | UNCOMPRESSED              [@id 0]
    | ANSIX962_COMPRESSED_PRIME [@id 1]
    | ANSIX962_COMPRESSED_CHAR2 [@id 2]
    (* reserved 248..255 *)
  [@@uint8_t] [@@sexp]]

  [%%cenum
  type ec_basis_type =
    | TRINOMIAL   [@id 0]
    | PENTANOMIAL [@id 1]
  [@@uint8_t] [@@sexp]]

  (** enum of all TLS ciphersuites *)
  [%%cenum
  type any_ciphersuite =
    | TLS_NULL_WITH_NULL_NULL                [@id 0x0000]
    | TLS_RSA_WITH_NULL_MD5                  [@id 0x0001]
    | TLS_RSA_WITH_NULL_SHA                  [@id 0x0002]
    | TLS_RSA_EXPORT_WITH_RC4_40_MD5         [@id 0x0003]
    | TLS_RSA_WITH_RC4_128_MD5               [@id 0x0004]
    | TLS_RSA_WITH_RC4_128_SHA               [@id 0x0005]
    | TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     [@id 0x0006]
    | TLS_RSA_WITH_IDEA_CBC_SHA              [@id 0x0007]
    | TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      [@id 0x0008]
    | TLS_RSA_WITH_DES_CBC_SHA               [@id 0x0009]
    | TLS_RSA_WITH_3DES_EDE_CBC_SHA          [@id 0x000A]
    | TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   [@id 0x000B]
    | TLS_DH_DSS_WITH_DES_CBC_SHA            [@id 0x000C]
    | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       [@id 0x000D]
    | TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   [@id 0x000E]
    | TLS_DH_RSA_WITH_DES_CBC_SHA            [@id 0x000F]
    | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       [@id 0x0010]
    | TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  [@id 0x0011]
    | TLS_DHE_DSS_WITH_DES_CBC_SHA           [@id 0x0012]
    | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      [@id 0x0013]
    | TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  [@id 0x0014]
    | TLS_DHE_RSA_WITH_DES_CBC_SHA           [@id 0x0015]
    | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      [@id 0x0016]
    | TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     [@id 0x0017]
    | TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  [@id 0x0019]
    (* MITM deprecated *)
    | TLS_DH_anon_WITH_RC4_128_MD5        [@id 0x0018]
    | TLS_DH_anon_WITH_DES_CBC_SHA        [@id 0x001A]
    | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA   [@id 0x001B]
    | RESERVED_SSL3_1                     [@id 0x001C] (* RFC5246 *)
    | RESERVED_SSL3_2                     [@id 0x001D] (* RFC5246 *)
    | TLS_KRB5_WITH_DES_CBC_SHA           [@id 0x001E] (* RFC2712 *)
    | TLS_KRB5_WITH_3DES_EDE_CBC_SHA      [@id 0x001F] (* RFC2712 *)
    | TLS_KRB5_WITH_RC4_128_SHA           [@id 0x0020] (*RFC2712 RFC6347*)
    | TLS_KRB5_WITH_IDEA_CBC_SHA          [@id 0x0021] (*RFC2712*)
    | TLS_KRB5_WITH_DES_CBC_MD5           [@id 0x0022] (*RFC2712*)
    | TLS_KRB5_WITH_3DES_EDE_CBC_MD5      [@id 0x0023] (*RFC2712*)
    | TLS_KRB5_WITH_RC4_128_MD5           [@id 0x0024] (*RFC2712, RFC6347*)
    | TLS_KRB5_WITH_IDEA_CBC_MD5          [@id 0x0025] (*RFC2712*)
    | TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA [@id 0x0026] (*RFC2712*)
    | TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA [@id 0x0027] (*RFC2712*)
    | TLS_KRB5_EXPORT_WITH_RC4_40_SHA     [@id 0x0028] (*RFC2712, RFC6347*)
    | TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 [@id 0x0029] (*RFC2712*)
    | TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 [@id 0x002A] (*RFC2712*)
    | TLS_KRB5_EXPORT_WITH_RC4_40_MD5     [@id 0x002B] (*RFC2712, RFC6347*)
    | TLS_PSK_WITH_NULL_SHA               [@id 0x002C] (*RFC4785*)
    | TLS_DHE_PSK_WITH_NULL_SHA           [@id 0x002D] (*RFC4785*)
    | TLS_RSA_PSK_WITH_NULL_SHA           [@id 0x002E] (*RFC4785*)
    (* from RFC 3268 *)
    | TLS_RSA_WITH_AES_128_CBC_SHA      [@id 0x002F]
    | TLS_DH_DSS_WITH_AES_128_CBC_SHA   [@id 0x0030]
    | TLS_DH_RSA_WITH_AES_128_CBC_SHA   [@id 0x0031]
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA  [@id 0x0032]
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA  [@id 0x0033]
    | TLS_DH_anon_WITH_AES_128_CBC_SHA  [@id 0x0034]
    | TLS_RSA_WITH_AES_256_CBC_SHA      [@id 0x0035]
    | TLS_DH_DSS_WITH_AES_256_CBC_SHA   [@id 0x0036]
    | TLS_DH_RSA_WITH_AES_256_CBC_SHA   [@id 0x0037]
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA  [@id 0x0038]
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA  [@id 0x0039]
    | TLS_DH_anon_WITH_AES_256_CBC_SHA  [@id 0x003A]
    (* from RFC 5246 *)
    | TLS_RSA_WITH_NULL_SHA256                 [@id 0x003B]
    | TLS_RSA_WITH_AES_128_CBC_SHA256          [@id 0x003C]
    | TLS_RSA_WITH_AES_256_CBC_SHA256          [@id 0x003D]
    | TLS_DH_DSS_WITH_AES_128_CBC_SHA256       [@id 0x003E]
    | TLS_DH_RSA_WITH_AES_128_CBC_SHA256       [@id 0x003F]
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256      [@id 0x0040]
    | TLS_RSA_WITH_CAMELLIA_128_CBC_SHA        [@id 0x0041] (*RFC5932*)
    | TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA     [@id 0x0042] (*RFC5932*)
    | TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA     [@id 0x0043] (*RFC5932*)
    | TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA    [@id 0x0044] (*RFC5932*)
    | TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA    [@id 0x0045] (*RFC5932*)
    | TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA    [@id 0x0046] (*RFC5932*)
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      [@id 0x0067]
    | TLS_DH_DSS_WITH_AES_256_CBC_SHA256       [@id 0x0068]
    | TLS_DH_RSA_WITH_AES_256_CBC_SHA256       [@id 0x0069]
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256      [@id 0x006A]
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      [@id 0x006B]
    | TLS_DH_anon_WITH_AES_128_CBC_SHA256      [@id 0x006C]
    | TLS_DH_anon_WITH_AES_256_CBC_SHA256      [@id 0x006D]
    | TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        [@id 0x0084] (*RFC5932*)
    | TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA     [@id 0x0085] (*RFC5932*)
    | TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA     [@id 0x0086] (*RFC5932*)
    | TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA    [@id 0x0087] (*RFC5932*)
    | TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    [@id 0x0088] (*RFC5932*)
    | TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA    [@id 0x0089] (*RFC5932*)
    | TLS_PSK_WITH_RC4_128_SHA                 [@id 0x008A] (*RFC4279, RFC6347*)
    | TLS_PSK_WITH_3DES_EDE_CBC_SHA            [@id 0x008B] (*RFC4279*)
    | TLS_PSK_WITH_AES_128_CBC_SHA             [@id 0x008C] (*RFC4279*)
    | TLS_PSK_WITH_AES_256_CBC_SHA             [@id 0x008D] (*RFC4279*)
    | TLS_DHE_PSK_WITH_RC4_128_SHA             [@id 0x008E] (*RFC4279, RFC6347*)
    | TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA        [@id 0x008F] (*RFC4279*)
    | TLS_DHE_PSK_WITH_AES_128_CBC_SHA         [@id 0x0090] (*RFC4279*)
    | TLS_DHE_PSK_WITH_AES_256_CBC_SHA         [@id 0x0091] (*RFC4279*)
    | TLS_RSA_PSK_WITH_RC4_128_SHA             [@id 0x0092] (*RFC4279, RFC6347*)
    | TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA        [@id 0x0093] (*RFC4279*)
    | TLS_RSA_PSK_WITH_AES_128_CBC_SHA         [@id 0x0094] (*RFC4279*)
    | TLS_RSA_PSK_WITH_AES_256_CBC_SHA         [@id 0x0095] (*RFC4279*)
    | TLS_RSA_WITH_SEED_CBC_SHA                [@id 0x0096] (*RFC4162*)
    | TLS_DH_DSS_WITH_SEED_CBC_SHA             [@id 0x0097] (*RFC4162*)
    | TLS_DH_RSA_WITH_SEED_CBC_SHA             [@id 0x0098] (*RFC4162*)
    | TLS_DHE_DSS_WITH_SEED_CBC_SHA            [@id 0x0099] (*RFC4162*)
    | TLS_DHE_RSA_WITH_SEED_CBC_SHA            [@id 0x009A] (*RFC4162*)
    | TLS_DH_anon_WITH_SEED_CBC_SHA            [@id 0x009B] (*RFC4162*)
    | TLS_RSA_WITH_AES_128_GCM_SHA256          [@id 0x009C] (*RFC5288*)
    | TLS_RSA_WITH_AES_256_GCM_SHA384          [@id 0x009D] (*RFC5288*)
    | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      [@id 0x009E] (*RFC5288*)
    | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      [@id 0x009F] (*RFC5288*)
    | TLS_DH_RSA_WITH_AES_128_GCM_SHA256       [@id 0x00A0] (*RFC5288*)
    | TLS_DH_RSA_WITH_AES_256_GCM_SHA384       [@id 0x00A1] (*RFC5288*)
    | TLS_DHE_DSS_WITH_AES_128_GCM_SHA256      [@id 0x00A2] (*RFC5288*)
    | TLS_DHE_DSS_WITH_AES_256_GCM_SHA384      [@id 0x00A3] (*RFC5288*)
    | TLS_DH_DSS_WITH_AES_128_GCM_SHA256       [@id 0x00A4] (*RFC5288*)
    | TLS_DH_DSS_WITH_AES_256_GCM_SHA384       [@id 0x00A5] (*RFC5288*)
    | TLS_DH_anon_WITH_AES_128_GCM_SHA256      [@id 0x00A6] (*RFC5288*)
    | TLS_DH_anon_WITH_AES_256_GCM_SHA384      [@id 0x00A7] (*RFC5288*)
    | TLS_PSK_WITH_AES_128_GCM_SHA256          [@id 0x00A8] (*RFC5487*)
    | TLS_PSK_WITH_AES_256_GCM_SHA384          [@id 0x00A9] (*RFC5487*)
    | TLS_DHE_PSK_WITH_AES_128_GCM_SHA256      [@id 0x00AA] (*RFC5487*)
    | TLS_DHE_PSK_WITH_AES_256_GCM_SHA384      [@id 0x00AB] (*RFC5487*)
    | TLS_RSA_PSK_WITH_AES_128_GCM_SHA256      [@id 0x00AC] (*RFC5487*)
    | TLS_RSA_PSK_WITH_AES_256_GCM_SHA384      [@id 0x00AD] (*RFC5487*)
    | TLS_PSK_WITH_AES_128_CBC_SHA256          [@id 0x00AE] (*RFC5487*)
    | TLS_PSK_WITH_AES_256_CBC_SHA384          [@id 0x00AF] (*RFC5487*)
    | TLS_PSK_WITH_NULL_SHA256                 [@id 0x00B0] (*RFC5487*)
    | TLS_PSK_WITH_NULL_SHA384                 [@id 0x00B1] (*RFC5487*)
    | TLS_DHE_PSK_WITH_AES_128_CBC_SHA256      [@id 0x00B2] (*RFC5487*)
    | TLS_DHE_PSK_WITH_AES_256_CBC_SHA384      [@id 0x00B3] (*RFC5487*)
    | TLS_DHE_PSK_WITH_NULL_SHA256             [@id 0x00B4] (*RFC5487*)
    | TLS_DHE_PSK_WITH_NULL_SHA384             [@id 0x00B5] (*RFC5487*)
    | TLS_RSA_PSK_WITH_AES_128_CBC_SHA256      [@id 0x00B6] (*RFC5487*)
    | TLS_RSA_PSK_WITH_AES_256_CBC_SHA384      [@id 0x00B7] (*RFC5487*)
    | TLS_RSA_PSK_WITH_NULL_SHA256             [@id 0x00B8] (*RFC5487*)
    | TLS_RSA_PSK_WITH_NULL_SHA384             [@id 0x00B9] (*RFC5487*)
    | TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     [@id 0x00BA] (*RFC5932*)
    | TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256  [@id 0x00BB] (*RFC5932*)
    | TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256  [@id 0x00BC] (*RFC5932*)
    | TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 [@id 0x00BD] (*RFC5932*)
    | TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 [@id 0x00BE] (*RFC5932*)
    | TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 [@id 0x00BF] (*RFC5932*)
    | TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     [@id 0x00C0] (*RFC5932*)
    | TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256  [@id 0x00C1] (*RFC5932*)
    | TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256  [@id 0x00C2] (*RFC5932*)
    | TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 [@id 0x00C3] (*RFC5932*)
    | TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 [@id 0x00C4] (*RFC5932*)
    | TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 [@id 0x00C5] (*RFC5932*)
    | TLS_EMPTY_RENEGOTIATION_INFO_SCSV        [@id 0x00FF] (*RFC5746*)
    | TLS_FALLBACK_SCSV                        [@id 0x5600] (*draft-ietf-tls-downgrade-scsv*)
    (* from RFC 4492 *)
    | TLS_ECDH_ECDSA_WITH_NULL_SHA                 [@id 0xC001]
    | TLS_ECDH_ECDSA_WITH_RC4_128_SHA              [@id 0xC002]
    | TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA         [@id 0xC003]
    | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA          [@id 0xC004]
    | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA          [@id 0xC005]
    | TLS_ECDHE_ECDSA_WITH_NULL_SHA                [@id 0xC006]
    | TLS_ECDHE_ECDSA_WITH_RC4_128_SHA             [@id 0xC007]
    | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        [@id 0xC008]
    | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA         [@id 0xC009]
    | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA         [@id 0xC00A]
    | TLS_ECDH_RSA_WITH_NULL_SHA                   [@id 0xC00B]
    | TLS_ECDH_RSA_WITH_RC4_128_SHA                [@id 0xC00C]
    | TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA           [@id 0xC00D]
    | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA            [@id 0xC00E]
    | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA            [@id 0xC00F]
    | TLS_ECDHE_RSA_WITH_NULL_SHA                  [@id 0xC010]
    | TLS_ECDHE_RSA_WITH_RC4_128_SHA               [@id 0xC011]
    | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          [@id 0xC012]
    | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA           [@id 0xC013]
    | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA           [@id 0xC014]
    | TLS_ECDH_anon_WITH_NULL_SHA                  [@id 0xC015]
    | TLS_ECDH_anon_WITH_RC4_128_SHA               [@id 0xC016]
    | TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA          [@id 0xC017]
    | TLS_ECDH_anon_WITH_AES_128_CBC_SHA           [@id 0xC018]
    | TLS_ECDH_anon_WITH_AES_256_CBC_SHA           [@id 0xC019]
    | TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA            [@id 0xC01A] (*RFC5054*)
    | TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA        [@id 0xC01B] (*RFC5054*)
    | TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA        [@id 0xC01C] (*RFC5054*)
    | TLS_SRP_SHA_WITH_AES_128_CBC_SHA             [@id 0xC01D] (*RFC5054*)
    | TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA         [@id 0xC01E] (*RFC5054*)
    | TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA         [@id 0xC01F] (*RFC5054*)
    | TLS_SRP_SHA_WITH_AES_256_CBC_SHA             [@id 0xC020] (*RFC5054*)
    | TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA         [@id 0xC021] (*RFC5054*)
    | TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA         [@id 0xC022] (*RFC5054*)
    | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      [@id 0xC023] (*RFC5289*)
    | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384      [@id 0xC024] (*RFC5289*)
    | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256       [@id 0xC025] (*RFC5289*)
    | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384       [@id 0xC026] (*RFC5289*)
    | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256        [@id 0xC027] (*RFC5289*)
    | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384        [@id 0xC028] (*RFC5289*)
    | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256         [@id 0xC029] (*RFC5289*)
    | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384         [@id 0xC02A]  (*RFC5289*)
    | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      [@id 0xC02B] (*RFC5289*)
    | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      [@id 0xC02C] (*RFC5289*)
    | TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256       [@id 0xC02D] (*RFC5289*)
    | TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384       [@id 0xC02E] (*RFC5289*)
    | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        [@id 0xC02F] (*RFC5289*)
    | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        [@id 0xC030] (*RFC5289*)
    | TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256         [@id 0xC031] (*RFC5289*)
    | TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384         [@id 0xC032] (*RFC5289*)
    | TLS_ECDHE_PSK_WITH_RC4_128_SHA               [@id 0xC033] (*RFC5489*)(*RFC6347*)
    | TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA          [@id 0xC034] (*RFC5489*)
    | TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA           [@id 0xC035] (*RFC5489*)
    | TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA           [@id 0xC036] (*RFC5489*)
    | TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256        [@id 0xC037] (*RFC5489*)
    | TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384        [@id 0xC038] (*RFC5489*)
    | TLS_ECDHE_PSK_WITH_NULL_SHA                  [@id 0xC039] (*RFC5489*)
    | TLS_ECDHE_PSK_WITH_NULL_SHA256               [@id 0xC03A] (*RFC5489*)
    | TLS_ECDHE_PSK_WITH_NULL_SHA384               [@id 0xC03B] (*RFC5489*)
    | TLS_RSA_WITH_ARIA_128_CBC_SHA256             [@id 0xC03C] (*RFC6209*)
    | TLS_RSA_WITH_ARIA_256_CBC_SHA384             [@id 0xC03D] (*RFC6209*)
    | TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256          [@id 0xC03E] (*RFC6209*)
    | TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384          [@id 0xC03F] (*RFC6209*)
    | TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256          [@id 0xC040] (*RFC6209*)
    | TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384          [@id 0xC041] (*RFC6209*)
    | TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256         [@id 0xC042] (*RFC6209*)
    | TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384         [@id 0xC043] (*RFC6209*)
    | TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256         [@id 0xC044] (*RFC6209*)
    | TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384         [@id 0xC045] (*RFC6209*)
    | TLS_DH_anon_WITH_ARIA_128_CBC_SHA256         [@id 0xC046] (*RFC6209*)
    | TLS_DH_anon_WITH_ARIA_256_CBC_SHA384         [@id 0xC047] (*RFC6209*)
    | TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256     [@id 0xC048] (*RFC6209*)
    | TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384     [@id 0xC049] (*RFC6209*)
    | TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256      [@id 0xC04A] (*RFC6209*)
    | TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384      [@id 0xC04B] (*RFC6209*)
    | TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256       [@id 0xC04C] (*RFC6209*)
    | TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384       [@id 0xC04D] (*RFC6209*)
    | TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256        [@id 0xC04E] (*RFC6209*)
    | TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384        [@id 0xC04F] (*RFC6209*)
    | TLS_RSA_WITH_ARIA_128_GCM_SHA256             [@id 0xC050] (*RFC6209*)
    | TLS_RSA_WITH_ARIA_256_GCM_SHA384             [@id 0xC051] (*RFC6209*)
    | TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256         [@id 0xC052] (*RFC6209*)
    | TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384         [@id 0xC053] (*RFC6209*)
    | TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256          [@id 0xC054] (*RFC6209*)
    | TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384          [@id 0xC055] (*RFC6209*)
    | TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256         [@id 0xC056] (*RFC6209*)
    | TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384         [@id 0xC057] (*RFC6209*)
    | TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256          [@id 0xC058] (*RFC6209*)
    | TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384          [@id 0xC059] (*RFC6209*)
    | TLS_DH_anon_WITH_ARIA_128_GCM_SHA256         [@id 0xC05A] (*RFC6209*)
    | TLS_DH_anon_WITH_ARIA_256_GCM_SHA384         [@id 0xC05B] (*RFC6209*)
    | TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256     [@id 0xC05C] (*RFC6209*)
    | TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384     [@id 0xC05D] (*RFC6209*)
    | TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256      [@id 0xC05E] (*RFC6209*)
    | TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384      [@id 0xC05F] (*RFC6209*)
    | TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256       [@id 0xC060] (*RFC6209*)
    | TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384       [@id 0xC061] (*RFC6209*)
    | TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256        [@id 0xC062] (*RFC6209*)
    | TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384        [@id 0xC063] (*RFC6209*)
    | TLS_PSK_WITH_ARIA_128_CBC_SHA256             [@id 0xC064] (*RFC6209*)
    | TLS_PSK_WITH_ARIA_256_CBC_SHA384             [@id 0xC065] (*RFC6209*)
    | TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256         [@id 0xC066] (*RFC6209*)
    | TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384         [@id 0xC067] (*RFC6209*)
    | TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256         [@id 0xC068] (*RFC6209*)
    | TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384         [@id 0xC069] (*RFC6209*)
    | TLS_PSK_WITH_ARIA_128_GCM_SHA256             [@id 0xC06A] (*RFC6209*)
    | TLS_PSK_WITH_ARIA_256_GCM_SHA384             [@id 0xC06B] (*RFC6209*)
    | TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256         [@id 0xC06C] (*RFC6209*)
    | TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384         [@id 0xC06D] (*RFC6209*)
    | TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256         [@id 0xC06E] (*RFC6209*)
    | TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384         [@id 0xC06F] (*RFC6209*)
    | TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256       [@id 0xC070] (*RFC6209*)
    | TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384       [@id 0xC071] (*RFC6209*)
    | TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 [@id 0xC072] (*RFC6367*)
    | TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 [@id 0xC073] (*RFC6367*)
    | TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  [@id 0xC074] (*RFC6367*)
    | TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  [@id 0xC075] (*RFC6367*)
    | TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   [@id 0xC076] (*RFC6367*)
    | TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   [@id 0xC077] (*RFC6367*)
    | TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    [@id 0xC078] (*RFC6367*)
    | TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    [@id 0xC079] (*RFC6367*)
    | TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256         [@id 0xC07A] (*RFC6367*)
    | TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384         [@id 0xC07B] (*RFC6367*)
    | TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     [@id 0xC07C] (*RFC6367*)
    | TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     [@id 0xC07D] (*RFC6367*)
    | TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256      [@id 0xC07E] (*RFC6367*)
    | TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384      [@id 0xC07F] (*RFC6367*)
    | TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256     [@id 0xC080] (*RFC6367*)
    | TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384     [@id 0xC081] (*RFC6367*)
    | TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256      [@id 0xC082] (*RFC6367*)
    | TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384      [@id 0xC083] (*RFC6367*)
    | TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256     [@id 0xC084] (*RFC6367*)
    | TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384     [@id 0xC085] (*RFC6367*)
    | TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 [@id 0xC086] (*RFC6367*)
    | TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 [@id 0xC087] (*RFC6367*)
    | TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  [@id 0xC088] (*RFC6367*)
    | TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  [@id 0xC089] (*RFC6367*)
    | TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256   [@id 0xC08A] (*RFC6367*)
    | TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384   [@id 0xC08B] (*RFC6367*)
    | TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256    [@id 0xC08C] (*RFC6367*)
    | TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384    [@id 0xC08D] (*RFC6367*)
    | TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256         [@id 0xC08E] (*RFC6367*)
    | TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384         [@id 0xC08F] (*RFC6367*)
    | TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256     [@id 0xC090] (*RFC6367*)
    | TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384     [@id 0xC091] (*RFC6367*)
    | TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256     [@id 0xC092] (*RFC6367*)
    | TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384     [@id 0xC093] (*RFC6367*)
    | TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256         [@id 0xC094] (*RFC6367*)
    | TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384         [@id 0xC095] (*RFC6367*)
    | TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256     [@id 0xC096] (*RFC6367*)
    | TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384     [@id 0xC097] (*RFC6367*)
    | TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256     [@id 0xC098] (*RFC6367*)
    | TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384     [@id 0xC099] (*RFC6367*)
    | TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   [@id 0xC09A] (*RFC6367*)
    | TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   [@id 0xC09B] (*RFC6367*)
    | TLS_RSA_WITH_AES_128_CCM                     [@id 0xC09C] (*RFC6655*)
    | TLS_RSA_WITH_AES_256_CCM                     [@id 0xC09D] (*RFC6655*)
    | TLS_DHE_RSA_WITH_AES_128_CCM                 [@id 0xC09E] (*RFC6655*)
    | TLS_DHE_RSA_WITH_AES_256_CCM                 [@id 0xC09F] (*RFC6655*)
    | TLS_RSA_WITH_AES_128_CCM_8                   [@id 0xC0A0] (*RFC6655*)
    | TLS_RSA_WITH_AES_256_CCM_8                   [@id 0xC0A1] (*RFC6655*)
    | TLS_DHE_RSA_WITH_AES_128_CCM_8               [@id 0xC0A2] (*RFC6655*)
    | TLS_DHE_RSA_WITH_AES_256_CCM_8               [@id 0xC0A3] (*RFC6655*)
    | TLS_PSK_WITH_AES_128_CCM                     [@id 0xC0A4] (*RFC6655*)
    | TLS_PSK_WITH_AES_256_CCM                     [@id 0xC0A5] (*RFC6655*)
    | TLS_DHE_PSK_WITH_AES_128_CCM                 [@id 0xC0A6] (*RFC6655*)
    | TLS_DHE_PSK_WITH_AES_256_CCM                 [@id 0xC0A7] (*RFC6655*)
    | TLS_PSK_WITH_AES_128_CCM_8                   [@id 0xC0A8] (*RFC6655*)
    | TLS_PSK_WITH_AES_256_CCM_8                   [@id 0xC0A9] (*RFC6655*)
    | TLS_PSK_DHE_WITH_AES_128_CCM_8               [@id 0xC0AA] (*RFC6655*)
    | TLS_PSK_DHE_WITH_AES_256_CCM_8               [@id 0xC0AB] (*RFC6655*)
  [@@uint16_t] [@@sexp]]
end

(** Ciphersuite definitions and some helper functions. *)
module Ciphersuite : sig

  (** sum type of all possible key exchange methods *)
  type key_exchange_algorithm =
    | RSA
    | DHE_RSA
  [@@deriving sexp]

  (** [needs_certificate kex] is a predicate which is true if the [kex] requires a server certificate *)
  val needs_certificate : key_exchange_algorithm -> bool

  (** [needs_server_kex kex] is a predicate which is true if the [kex] requires a server key exchange messag *)
  val needs_server_kex : key_exchange_algorithm -> bool

  (** [required_keytype_and_usage kex] is [(keytype, usage)] which a certificate must have if it is used in the given [kex] method *)
  val required_keytype_and_usage : key_exchange_algorithm -> X509.key_type * X509.Extension.key_usage

  type stream_cipher =
    | RC4_128
  [@@deriving sexp]

  type block_cipher =
    | TRIPLE_DES_EDE_CBC
    | AES_128_CBC
    | AES_256_CBC
  [@@deriving sexp]

  type aead_cipher =
    | AES_128_CCM
    | AES_256_CCM
    | AES_128_GCM
    | AES_256_GCM
  [@@deriving sexp]

  type payload_protection =
    | Stream of stream_cipher * Nocrypto.Hash.hash
    | Block of block_cipher * Nocrypto.Hash.hash
    | AEAD of aead_cipher
  [@@deriving sexp]

  (** [key_length iv payload_protection] is [(key size, IV size, mac size)] where key IV, and mac sizes are the required bytes for the given [payload_protection] *)
  val key_length : unit option -> payload_protection -> int * int * int

  type ciphersuite = [
    | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    | `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    | `TLS_RSA_WITH_AES_256_CBC_SHA256
    | `TLS_RSA_WITH_AES_128_CBC_SHA256
    | `TLS_RSA_WITH_AES_256_CBC_SHA
    | `TLS_RSA_WITH_AES_128_CBC_SHA
    | `TLS_RSA_WITH_3DES_EDE_CBC_SHA
    | `TLS_RSA_WITH_RC4_128_SHA
    | `TLS_RSA_WITH_RC4_128_MD5
    | `TLS_RSA_WITH_AES_128_GCM_SHA256
    | `TLS_RSA_WITH_AES_256_GCM_SHA384
    | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    | `TLS_DHE_RSA_WITH_AES_256_CCM
    | `TLS_DHE_RSA_WITH_AES_128_CCM
    | `TLS_RSA_WITH_AES_256_CCM
    | `TLS_RSA_WITH_AES_128_CCM
  ]  [@@deriving sexp]

  val any_ciphersuite_to_ciphersuite : Packet.any_ciphersuite -> ciphersuite option

  val ciphersuite_to_any_ciphersuite : ciphersuite -> Packet.any_ciphersuite

  val ciphersuite_to_string : ciphersuite -> string

  (** [get_kex_privprot ciphersuite] is [(kex, privacy_protection)] where it dissects the [ciphersuite] into a pair containing the key exchange method [kex], and its [privacy_protection] *)
  val get_kex_privprot : ciphersuite -> key_exchange_algorithm * payload_protection

  (** [ciphersuite_kex ciphersuite] is [kex], first projection of [get_kex_privprot] *)
  val ciphersuite_kex : ciphersuite -> key_exchange_algorithm

  (** [ciphersuite_privprot ciphersuite] is [privprot], second projection of [get_kex_privprot] *)
  val ciphersuite_privprot : ciphersuite -> payload_protection

  val ciphersuite_fs : ciphersuite -> bool

  val ciphersuite_tls12_only : ciphersuite -> bool
end

module Core : sig
  type tls_version =
    | TLS_1_0
    | TLS_1_1
    | TLS_1_2
  [@@deriving sexp]

  val pair_of_tls_version : tls_version -> int * int

  val tls_version_of_pair : int * int -> tls_version option

  type tls_any_version =
  | SSL_3
  | Supported of tls_version
  | TLS_1_X of int
  [@@deriving sexp]

  val any_version_to_version : tls_any_version -> tls_version option

  val version_eq : tls_any_version -> tls_version -> bool

  val version_ge : tls_any_version -> tls_version -> bool

  val tls_any_version_of_pair : int * int -> tls_any_version option

  val pair_of_tls_any_version : tls_any_version -> int * int

  val max_protocol_version : tls_version * tls_version -> tls_version
  val min_protocol_version : tls_version * tls_version -> tls_version

  type tls_hdr = {
    content_type : Packet.content_type;
    version      : tls_any_version;
  } [@@deriving sexp]

  module SessionID : sig
    type t = Cstruct.t
    val compare : t -> t -> int
    val hash : t -> int
    val equal : t -> t -> bool
  end

  type client_extension = [
    | `Hostname of string
    | `MaxFragmentLength of Packet.max_fragment_length
    | `EllipticCurves of Packet.named_curve_type list
    | `ECPointFormats of Packet.ec_point_format list
    | `SecureRenegotiation of Cstruct.t
    | `Padding of int
    | `SignatureAlgorithms of (Nocrypto.Hash.hash * Packet.signature_algorithm_type) list
    | `UnknownExtension of (int * Cstruct.t)
    | `ExtendedMasterSecret
  ] [@@deriving sexp]

  type server_extension = [
    | `Hostname
    | `MaxFragmentLength of Packet.max_fragment_length
    | `ECPointFormats of Packet.ec_point_format list
    | `SecureRenegotiation of Cstruct.t
    | `UnknownExtension of (int * Cstruct.t)
    | `ExtendedMasterSecret
  ] [@@deriving sexp]

  type client_hello = {
    client_version : tls_any_version;
    client_random  : Cstruct.t;
    sessionid      : SessionID.t option;
    ciphersuites   : Packet.any_ciphersuite list;
    extensions     : client_extension list
  } [@@deriving sexp]

  type server_hello = {
    server_version : tls_version;
    server_random  : Cstruct.t;
    sessionid      : SessionID.t option;
    ciphersuite    : Ciphersuite.ciphersuite;
    extensions     : server_extension list
  } [@@deriving sexp]

  type dh_parameters = {
    dh_p  : Cstruct.t;
    dh_g  : Cstruct.t;
    dh_Ys : Cstruct.t;
  } [@@deriving sexp]

  type ec_curve = {
    a : Cstruct.t;
    b : Cstruct.t
  } [@@deriving sexp]

  type ec_prime_parameters = {
    prime    : Cstruct.t;
    curve    : ec_curve;
    base     : Cstruct.t;
    order    : Cstruct.t;
    cofactor : Cstruct.t;
    public   : Cstruct.t
  } [@@deriving sexp]

  type ec_char_parameters = {
    m        : int;
    basis    : Packet.ec_basis_type;
    ks       : Cstruct.t list;
    curve    : ec_curve;
    base     : Cstruct.t;
    order    : Cstruct.t;
    cofactor : Cstruct.t;
    public   : Cstruct.t
  } [@@deriving sexp]

  type ec_parameters =
    | ExplicitPrimeParameters of ec_prime_parameters
    | ExplicitCharParameters of ec_char_parameters
    | NamedCurveParameters of (Packet.named_curve_type * Cstruct.t)
  [@@deriving sexp]

  type tls_handshake =
    | HelloRequest
    | ServerHelloDone
    | ClientHello of client_hello
    | ServerHello of server_hello
    | Certificate of Cstruct.t list
    | ServerKeyExchange of Cstruct.t
    | CertificateRequest of Cstruct.t
    | ClientKeyExchange of Cstruct.t
    | CertificateVerify of Cstruct.t
    | Finished of Cstruct.t
  [@@deriving sexp]

  type tls_alert = Packet.alert_level * Packet.alert_type [@@deriving sexp]

  type tls_body =
    | TLS_ChangeCipherSpec
    | TLS_ApplicationData
    | TLS_Alert of tls_alert
    | TLS_Handshake of tls_handshake
  [@@deriving sexp]

  (** the master secret of a TLS connection *)
  type master_secret = Cstruct.t [@@deriving sexp]

  (** information about an open session *)
  type epoch_data = {
    protocol_version       : tls_version ;
    ciphersuite            : Ciphersuite.ciphersuite ;
    peer_random            : Cstruct.t ;
    peer_certificate_chain : X509.t list ;
    peer_certificate       : X509.t option ;
    peer_name              : string option ;
    trust_anchor           : X509.t option ;
    received_certificates  : X509.t list ;
    own_random             : Cstruct.t ;
    own_certificate        : X509.t list ;
    own_private_key        : Nocrypto.Rsa.priv option ;
    own_name               : string option ;
    master_secret          : master_secret ;
    session_id             : SessionID.t ;
    extended_ms            : bool ;
  } [@@deriving sexp]
end

module Reader : sig
  type error =
    | TrailingBytes  of string
    | WrongLength    of string
    | Unknown        of string
    | Underflow
    | Overflow       of int
    | UnknownVersion of (int * int)
    | UnknownContent of int

  val error_of_sexp : Sexplib.Sexp.t -> error
  val sexp_of_error : error -> Sexplib.Sexp.t

  type 'a result = ('a, error) Result.result

  val parse_version     : Cstruct.t -> Core.tls_version result
  val parse_any_version : Cstruct.t -> Core.tls_any_version result
  val parse_record      : Cstruct.t ->
    [ `Record of (Core.tls_hdr * Cstruct.t) * Cstruct.t
    | `Fragment of Cstruct.t
    ] result

  val parse_handshake_frame : Cstruct.t -> (Cstruct.t option * Cstruct.t)
  val parse_handshake : Cstruct.t -> Core.tls_handshake result

  val parse_alert     : Cstruct.t -> Core.tls_alert result

  val parse_change_cipher_spec   : Cstruct.t -> unit result

  val parse_certificate_request     : Cstruct.t -> (Packet.client_certificate_type list * Cstruct.t list) result
  val parse_certificate_request_1_2 : Cstruct.t -> (Packet.client_certificate_type list * (Nocrypto.Hash.hash * Packet.signature_algorithm_type) list * Cstruct.t list) result

  val parse_dh_parameters        : Cstruct.t -> (Core.dh_parameters * Cstruct.t * Cstruct.t) result
  val parse_digitally_signed     : Cstruct.t -> Cstruct.t result
  val parse_digitally_signed_1_2 : Cstruct.t -> (Nocrypto.Hash.hash * Packet.signature_algorithm_type * Cstruct.t) result
end

module Writer : sig
  val assemble_protocol_version : Core.tls_version -> Cstruct.t

  val assemble_handshake : Core.tls_handshake -> Cstruct.t

  val assemble_hdr : Core.tls_version -> (Packet.content_type * Cstruct.t) -> Cstruct.t

  val assemble_alert : ?level:Packet.alert_level -> Packet.alert_type -> Cstruct.t

  val assemble_change_cipher_spec : Cstruct.t

  val assemble_dh_parameters : Core.dh_parameters -> Cstruct.t

  val assemble_digitally_signed : Cstruct.t -> Cstruct.t

  val assemble_digitally_signed_1_2 : Nocrypto.Hash.hash -> Packet.signature_algorithm_type -> Cstruct.t -> Cstruct.t

  val assemble_certificate_request : Packet.client_certificate_type list -> Cstruct.t list -> Cstruct.t

  val assemble_certificate_request_1_2 : Packet.client_certificate_type list -> (Nocrypto.Hash.hash * Packet.signature_algorithm_type) list -> Cstruct.t list -> Cstruct.t
end

module Config : sig
  open Nocrypto
  open Core

  (** Configuration of the TLS stack *)

  (** {1 Config type} *)

  (** certificate chain and private key of the first certificate *)
  type certchain = X509.t list * Nocrypto.Rsa.priv

  (** polymorphic variant of own certificates *)
  type own_cert = [
    | `None
    | `Single of certchain
    | `Multiple of certchain list
    | `Multiple_default of certchain * certchain list
  ]

  type session_cache = SessionID.t -> epoch_data option

  (** configuration parameters *)
  type config = private {
    ciphers           : Ciphersuite.ciphersuite list ; (** ordered list (regarding preference) of supported cipher suites *)
    protocol_versions : tls_version * tls_version ; (** supported protocol versions (min, max) *)
    hashes            : Hash.hash list ; (** ordered list of supported hash algorithms (regarding preference) *)
    use_reneg         : bool ; (** endpoint should accept renegotiation requests *)
    authenticator     : X509.Authenticator.a option ; (** optional X509 authenticator *)
    peer_name         : string option ; (** optional name of other endpoint (used for SNI RFC4366) *)
    own_certificates  : own_cert ; (** optional default certificate chain and other certificate chains *)
    session_cache     : session_cache ;
    cached_session    : epoch_data option ;
  }

  val config_of_sexp : Sexplib.Sexp.t -> config
  val sexp_of_config : config -> Sexplib.Sexp.t

  (** opaque type of a client configuration *)
  type client

  val client_of_sexp : Sexplib.Sexp.t -> client
  val sexp_of_client : client -> Sexplib.Sexp.t

  (** opaque type of a server configuration *)
  type server

  val server_of_sexp : Sexplib.Sexp.t -> server
  val sexp_of_server : server -> Sexplib.Sexp.t

  (** {1 Constructors} *)

  (** [client authenticator ?ciphers ?version ?hashes ?reneg ?certificates] is [client] configuration with the given parameters *)
  (** @raise Invalid_argument if the configuration is invalid *)
  val client :
    authenticator   : X509.Authenticator.a ->
    ?ciphers        : Ciphersuite.ciphersuite list ->
    ?version        : tls_version * tls_version ->
    ?hashes         : Hash.hash list ->
    ?reneg          : bool ->
    ?certificates   : own_cert ->
    ?cached_session : epoch_data ->
    unit -> client

  (** [server ?ciphers ?version ?hashes ?reneg ?certificates ?authenticator] is [server] configuration with the given parameters *)
  (** @raise Invalid_argument if the configuration is invalid *)
  val server :
    ?ciphers       : Ciphersuite.ciphersuite list ->
    ?version       : tls_version * tls_version ->
    ?hashes        : Hash.hash list ->
    ?reneg         : bool ->
    ?certificates  : own_cert ->
    ?authenticator : X509.Authenticator.a ->
    ?session_cache : session_cache ->
    unit -> server

  (** [peer client name] is [client] with [name] as [peer_name] *)
  val peer : client -> string -> client

  (** {1 Utility functions} *)

  (** [default_hashes] is a list of hash algorithms used by default *)
  val default_hashes  : Hash.hash list

  (** [supported_hashes] is a list of supported hash algorithms by this library *)
  val supported_hashes  : Hash.hash list

  (** [min_dh_size] is minimal diffie hellman group size in bits (currently 1024) *)
  val min_dh_size : int

  (** [dh_group] is the default Diffie-Hellman group (currently the
      ffdhe2048 group from
      {{:https://www.ietf.org/id/draft-ietf-tls-negotiated-ff-dhe-10.txt}Negotiated
      Finite Field Diffie-Hellman Ephemeral Parameters for TLS}) *)
  val dh_group : Dh.group

  (** [min_rsa_key_size] is minimal RSA modulus key size in bits (currently 1024) *)
  val min_rsa_key_size : int

  (** Cipher selection *)
  module Ciphers : sig

    open Ciphersuite

    (** Cipher selection related utilities. *)

    (** {1 Cipher selection} *)

    val default : ciphersuite list
    (** [default] is a list of ciphersuites this library uses by default. *)

    val supported : ciphersuite list
    (** [supported] is a list of ciphersuites this library supports
        (larger than [default]). *)

    val fs : ciphersuite list
    (** [fs] is a list of ciphersuites which provide forward secrecy
        (sublist of [default]). *)

    val fs_of : ciphersuite list -> ciphersuite list
    (** [fs_of ciphers] selects all ciphersuites which provide forward
        secrecy from [ciphers]. *)
  end

  (** {1 Internal use only} *)

  (** [of_client client] is a client configuration for [client] *)
  val of_client : client -> config

  (** [of_server server] is a server configuration for [server] *)
  val of_server : server -> config

end

module Engine : sig
  (** {1 Abstract state type} *)

  (** The abstract type of a TLS state, with
      {{!Encoding.Pem.Certificate}encoding and decoding to PEM}. *)
  type state

  (** {1 Constructors} *)

  (** [client client] is [tls * out] where [tls] is the initial state,
      and [out] the initial client hello *)
  val client : Config.client -> (state * Cstruct.t)

  (** [server server] is [tls] where [tls] is the initial server
      state *)
  val server : Config.server -> state

  (** {1 Protocol failures} *)

  (** failures which can be mitigated by reconfiguration *)
  type error = [
    | `AuthenticationFailure of X509.Validation.validation_error
    | `NoConfiguredCiphersuite of Ciphersuite.ciphersuite list
    | `NoConfiguredVersion of Core.tls_version
    | `NoConfiguredHash of Nocrypto.Hash.hash list
    | `NoMatchingCertificateFound of string
    | `NoCertificateConfigured
    | `CouldntSelectCertificate
  ]

  (** failures from received garbage or lack of features *)
  type fatal = [
    | `NoSecureRenegotiation
    | `NoCiphersuite of Packet.any_ciphersuite list
    | `NoVersion of Core.tls_any_version
    | `ReaderError of Reader.error
    | `NoCertificateReceived
    | `NotRSACertificate
    | `NotRSASignature
    | `KeyTooSmall
    | `RSASignatureMismatch
    | `RSASignatureVerificationFailed
    | `HashAlgorithmMismatch
    | `BadCertificateChain
    | `MACMismatch
    | `MACUnderflow
    | `RecordOverflow of int
    | `UnknownRecordVersion of int * int
    | `UnknownContentType of int
    | `CannotHandleApplicationDataYet
    | `NoHeartbeat
    | `BadRecordVersion of Core.tls_any_version
    | `BadFinished
    | `HandshakeFragmentsNotEmpty
    | `InvalidDH
    | `InvalidRenegotiation
    | `InvalidClientHello
    | `InvalidServerHello
    | `InvalidRenegotiationVersion of Core.tls_version
    | `InappropriateFallback
    | `UnexpectedCCS
    | `UnexpectedHandshake of Core.tls_handshake
    | `InvalidCertificateUsage
    | `InvalidCertificateExtendedUsage
    | `InvalidSession
  ]

  (** type of failures *)
  type failure = [
    | `Error of error
    | `Fatal of fatal
  ]

  (** [alert_of_failure failure] is [alert], the TLS alert type for this failure. *)
  val alert_of_failure : failure -> Packet.alert_type

  (** [string_of_failure failure] is [string], the string representation of the [failure]. *)
  val string_of_failure : failure -> string

  (** [failure_of_sexp sexp] is [failure], the unmarshalled [sexp]. *)
  val failure_of_sexp : Sexplib.Sexp.t -> failure

  (** [sexp_of_failure failure] is [sexp], the marshalled [failure]. *)
  val sexp_of_failure : failure -> Sexplib.Sexp.t

  (** {1 Protocol handling} *)

  (** result type of {!handle_tls}: either failed to handle the incoming
      buffer ([`Fail]) with {!failure} and potentially a message to send
      to the other endpoint, or sucessful operation ([`Ok]) with a new
      {!state}, an end of file ([`Eof]), or an incoming ([`Alert]).
      Possibly some [`Response] to the other endpoint is needed, and
      potentially some [`Data] for the application was received. *)
  type ret = [
    | `Ok of [ `Ok of state | `Eof | `Alert of Packet.alert_type ]
             * [ `Response of Cstruct.t option ]
             * [ `Data of Cstruct.t option ]
    | `Fail of failure * [ `Response of Cstruct.t ]
  ]

  (** [handle_tls state buffer] is [ret], depending on incoming [state]
      and [buffer], the result is the appropriate {!ret} *)
  val handle_tls           : state -> Cstruct.t -> ret

  (** [can_handle_appdata state] is a predicate which indicates when the
      connection has already completed a handshake. *)
  val can_handle_appdata    : state -> bool

  (** [send_application_data tls outs] is [(tls' * out) option] where
      [tls'] is the new tls state, and [out] the cstruct to send over the
      wire (encrypted [outs]). *)
  val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

  (** [send_close_notify tls] is [tls' * out] where [tls'] is the new
      tls state, and out the (possible encrypted) close notify alert. *)
  val send_close_notify     : state -> state * Cstruct.t

  (** [reneg tls] initiates a renegotation on [tls]. It is [tls' * out]
      where [tls'] is the new tls state, and [out] either a client hello
      or hello request (depending on which communication endpoint [tls]
      is). *)
  val reneg                 : state -> (state * Cstruct.t) option

  (** {1 Session information} *)

  (** polymorphic variant of session information.  The first variant
      [`InitialEpoch] will only be used for TLS states without completed
      handshake.  The second variant, [`Epoch], contains actual session
      data. *)
  type epoch = [
    | `InitialEpoch
    | `Epoch of Core.epoch_data
  ]

  (** [epoch_of_sexp sexp] is [epoch], the unmarshalled [sexp]. *)
  val epoch_of_sexp : Sexplib.Sexp.t -> epoch

  (** [sexp_of_epoch epoch] is [sexp], the marshalled [epoch]. *)
  val sexp_of_epoch : epoch -> Sexplib.Sexp.t

  (** [epoch state] is [epoch], which contains the session
      information. *)
  val epoch : state -> epoch
end

