(* RFC 2246 *)

open Printf
open Cstruct

(* HACK: 24 bits type not in cstruct *)
cstruct uint24_len {
  uint16_t len1;
  uint8_t  len2
} as big_endian

let rec pow a = function
  | 0 -> 1
  | 1 -> a
  | n -> let b = pow a (n / 2) in
         b * b * (if n mod 2 = 0 then 1 else a)

let get_uint24_len buf =
  (get_uint24_len_len1 buf) * (pow 2 8) + (get_uint24_len_len2 buf)

cenum content_type {
  CHANGE_CIPHER_SPEC = 20;
  ALERT              = 21;
  HANDSHAKE          = 22;
  APPLICATION_DATA   = 23;
  HEARTBEAT          = 24
} as uint8_t

cstruct tls_h {
  uint8_t  content_type;
  uint8_t  major_version;
  uint8_t  minor_version;
  uint16_t length
} as big_endian

type tls_hdr = {
  content_type : content_type;
  major        : int;
  minor        : int
}

let assemble_hdr length packet buf =
  Cstruct.set_uint8 buf 0 (content_type_to_int packet.content_type);
  Cstruct.set_uint8 buf 1 packet.major;
  Cstruct.set_uint8 buf 2 packet.major;
  Cstruct.BE.set_uint16 buf 3 length

let parse_hdr buf =
  let content_type = match int_to_content_type (get_tls_h_content_type buf) with
    | Some x -> x in
  let major = get_tls_h_major_version buf in
  let minor = get_tls_h_minor_version buf in
  let len = get_tls_h_length buf in
  let payload = Cstruct.sub buf 5 len in
  ( { content_type; major; minor }, payload)

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

cstruct handshake {
  uint8_t handshake_type;
  uint16_t handshake_length;
  uint8_t handshake_length2
} as big_endian

let get_varlength buf = function
  | 0 -> (None, 0)
  | n -> let rec go buf len = function
           | 0 -> len
           | n -> go (Cstruct.shift buf 1) ((Cstruct.get_uint8 buf 0) + len * (pow 2 8)) (n - 1)
         in
         let len = go buf 0 n in
         let total = len + n in
         (Some (Cstruct.sub buf n total), total)

cenum ciphersuite {
  TLS_NULL_WITH_NULL_NULL                = 0x0000;

  TLS_RSA_WITH_NULL_MD5                  = 0x0001;
  TLS_RSA_WITH_NULL_SHA                  = 0x0002;
  TLS_RSA_EXPORT_WITH_RC4_40_MD5         = 0x0003;
  TLS_RSA_WITH_RC4_128_MD5               = 0x0004;
  TLS_RSA_WITH_RC4_128_SHA               = 0x0005;
  TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     = 0x0006;
  TLS_RSA_WITH_IDEA_CBC_SHA              = 0x0007;
  TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      = 0x0008;
  TLS_RSA_WITH_DES_CBC_SHA               = 0x0009;
  TLS_RSA_WITH_3DES_EDE_CBC_SHA          = 0x000A;
  TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   = 0x000B;
  TLS_DH_DSS_WITH_DES_CBC_SHA            = 0x000C;
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       = 0x000D;
  TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   = 0x000E;
  TLS_DH_RSA_WITH_DES_CBC_SHA            = 0x000F;
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       = 0x0010;
  TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x0011;
  TLS_DHE_DSS_WITH_DES_CBC_SHA           = 0x0012;
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      = 0x0013;
  TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x0014;
  TLS_DHE_RSA_WITH_DES_CBC_SHA           = 0x0015;
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0016;
  TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     = 0x0017;
  TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  = 0x0019;

  (* MITM deprecated *)
  TLS_DH_anon_WITH_RC4_128_MD5           = 0x0018;
  TLS_DH_anon_WITH_DES_CBC_SHA           = 0x001A;
  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      = 0x001B;

  RESERVED_SSL3_1                        = 0x001C; (* RFC5246 *)
  RESERVED_SSL3_2                        = 0x001D; (* RFC5246 *)
  TLS_KRB5_WITH_DES_CBC_SHA              = 0x001E; (* RFC2712 *)
  TLS_KRB5_WITH_3DES_EDE_CBC_SHA         = 0x001F; (* RFC2712 *)

  TLS_KRB5_WITH_RC4_128_SHA = 0x0020; (*RFC2712 RFC6347*)
  TLS_KRB5_WITH_IDEA_CBC_SHA = 0x0021; (*RFC2712*)
  TLS_KRB5_WITH_DES_CBC_MD5 = 0x0022; (*RFC2712*)
  TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x0023; (*RFC2712*)
  TLS_KRB5_WITH_RC4_128_MD5 = 0x0024; (*RFC2712, RFC6347*)
  TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x0025; (*RFC2712*)
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026; (*RFC2712*)
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027; (*RFC2712*)
  TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x0028; (*RFC2712, RFC6347*)
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029; (*RFC2712*)
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A; (*RFC2712*)
  TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x002B; (*RFC2712, RFC6347*)
  TLS_PSK_WITH_NULL_SHA = 0x002C; (*RFC4785*)
  TLS_DHE_PSK_WITH_NULL_SHA = 0x002D; (*RFC4785*)
  TLS_RSA_PSK_WITH_NULL_SHA = 0x002E; (*RFC4785*)

  (* from RFC 3268 *)
  TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F;
  TLS_DH_DSS_WITH_AES_128_CBC_SHA   = 0x0030;
  TLS_DH_RSA_WITH_AES_128_CBC_SHA   = 0x0031;
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032;
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033;
  TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034;
  TLS_RSA_WITH_AES_256_CBC_SHA      = 0x0035;
  TLS_DH_DSS_WITH_AES_256_CBC_SHA   = 0x0036;
  TLS_DH_RSA_WITH_AES_256_CBC_SHA   = 0x0037;
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA  = 0x0038;
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x0039;
  TLS_DH_anon_WITH_AES_256_CBC_SHA  = 0x003A;

  (* from RFC 5246 *)
  TLS_RSA_WITH_NULL_SHA256              = 0x003B;
  TLS_RSA_WITH_AES_128_CBC_SHA256       = 0x003C;
  TLS_RSA_WITH_AES_256_CBC_SHA256       = 0x003D;
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = 0x003E;
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = 0x003F;
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = 0x0040;


  TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041; (*RFC5932*)
  TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0042; (*RFC5932*)
  TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043; (*RFC5932*)
  TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0044; (*RFC5932*)
  TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045; (*RFC5932*)
  TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x0046; (*RFC5932*)

  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = 0x0067;
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = 0x0068;
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = 0x0069;
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = 0x006A;
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = 0x006B;
  TLS_DH_anon_WITH_AES_128_CBC_SHA256   = 0x006C;
  TLS_DH_anon_WITH_AES_256_CBC_SHA256   = 0x006D;

  TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084; (*RFC5932*)
  TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0085; (*RFC5932*)
  TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086; (*RFC5932*)
  TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087; (*RFC5932*)
  TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088; (*RFC5932*)
  TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x0089; (*RFC5932*)
  TLS_PSK_WITH_RC4_128_SHA = 0x008A; (*RFC4279, RFC6347*)
  TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x008B; (*RFC4279*)
  TLS_PSK_WITH_AES_128_CBC_SHA = 0x008C; (*RFC4279*)
  TLS_PSK_WITH_AES_256_CBC_SHA = 0x008D; (*RFC4279*)
  TLS_DHE_PSK_WITH_RC4_128_SHA = 0x008E; (*RFC4279, RFC6347*)
  TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x008F; (*RFC4279*)
  TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090; (*RFC4279*)
  TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091; (*RFC4279*)
  TLS_RSA_PSK_WITH_RC4_128_SHA = 0x0092; (*RFC4279, RFC6347*)
  TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x0093; (*RFC4279*)
  TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094; (*RFC4279*)
  TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095; (*RFC4279*)
  TLS_RSA_WITH_SEED_CBC_SHA = 0x0096; (*RFC4162*)
  TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x0097; (*RFC4162*)
  TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098; (*RFC4162*)
  TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x0099; (*RFC4162*)
  TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009A; (*RFC4162*)
  TLS_DH_anon_WITH_SEED_CBC_SHA = 0x009B; (*RFC4162*)
  TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C; (*RFC5288*)
  TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D; (*RFC5288*)
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E; (*RFC5288*)
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F; (*RFC5288*)
  TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00A0; (*RFC5288*)
  TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00A1; (*RFC5288*)
  TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00A2; (*RFC5288*)
  TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00A3; (*RFC5288*)
  TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00A4; (*RFC5288*)
  TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00A5; (*RFC5288*)
  TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0x00A6; (*RFC5288*)
  TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0x00A7; (*RFC5288*)
  TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8; (*RFC5487*)
  TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9; (*RFC5487*)
  TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA; (*RFC5487*)
  TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB; (*RFC5487*)
  TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC; (*RFC5487*)
  TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD; (*RFC5487*)
  TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE; (*RFC5487*)
  TLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF; (*RFC5487*)
  TLS_PSK_WITH_NULL_SHA256 = 0x00B0; (*RFC5487*)
  TLS_PSK_WITH_NULL_SHA384 = 0x00B1; (*RFC5487*)
  TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2; (*RFC5487*)
  TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3; (*RFC5487*)
  TLS_DHE_PSK_WITH_NULL_SHA256 = 0x00B4; (*RFC5487*)
  TLS_DHE_PSK_WITH_NULL_SHA384 = 0x00B5; (*RFC5487*)
  TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6; (*RFC5487*)
  TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7; (*RFC5487*)
  TLS_RSA_PSK_WITH_NULL_SHA256 = 0x00B8; (*RFC5487*)
  TLS_RSA_PSK_WITH_NULL_SHA384 = 0x00B9; (*RFC5487*)
  TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BA; (*RFC5932*)
  TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BB; (*RFC5932*)
  TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BC; (*RFC5932*)
  TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BD; (*RFC5932*)
  TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BE; (*RFC5932*)
  TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BF; (*RFC5932*)
  TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C0; (*RFC5932*)
  TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C1; (*RFC5932*)
  TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C2; (*RFC5932*)
  TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C3; (*RFC5932*)
  TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C4; (*RFC5932*)
  TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C5; (*RFC5932*)
  TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF; (*RFC5746*)


  (* from RFC 4492 *)
  TLS_ECDH_ECDSA_WITH_NULL_SHA           = 0xC001;
  TLS_ECDH_ECDSA_WITH_RC4_128_SHA        = 0xC002;
  TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA   = 0xC003;
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    = 0xC004;
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA    = 0xC005;

  TLS_ECDHE_ECDSA_WITH_NULL_SHA          = 0xC006;
  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       = 0xC007;
  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  = 0xC008;
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   = 0xC009;
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   = 0xC00A;

  TLS_ECDH_RSA_WITH_NULL_SHA             = 0xC00B;
  TLS_ECDH_RSA_WITH_RC4_128_SHA          = 0xC00C;
  TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA     = 0xC00D;
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA      = 0xC00E;
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA      = 0xC00F;

  TLS_ECDHE_RSA_WITH_NULL_SHA            = 0xC010;
  TLS_ECDHE_RSA_WITH_RC4_128_SHA         = 0xC011;
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    = 0xC012;
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     = 0xC013;
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     = 0xC014;

  TLS_ECDH_anon_WITH_NULL_SHA            = 0xC015;
  TLS_ECDH_anon_WITH_RC4_128_SHA         = 0xC016;
  TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA    = 0xC017;
  TLS_ECDH_anon_WITH_AES_128_CBC_SHA     = 0xC018;
  TLS_ECDH_anon_WITH_AES_256_CBC_SHA     = 0xC019;

  TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A; (*RFC5054*)
  TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B; (*RFC5054*)
  TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C; (*RFC5054*)
  TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D; (*RFC5054*)
  TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E; (*RFC5054*)
  TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F; (*RFC5054*)
  TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020; (*RFC5054*)
  TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021; (*RFC5054*)
  TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022; (*RFC5054*)
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023; (*RFC5289*)
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024; (*RFC5289*)
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025; (*RFC5289*)
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026; (*RFC5289*)
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027; (*RFC5289*)
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028; (*RFC5289*)
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029; (*RFC5289*)
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A;  (*RFC5289*)
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B; (*RFC5289*)
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C; (*RFC5289*)
  TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D; (*RFC5289*)
  TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E; (*RFC5289*)
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F; (*RFC5289*)
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030; (*RFC5289*)
  TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031; (*RFC5289*)
  TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032; (*RFC5289*)
  TLS_ECDHE_PSK_WITH_RC4_128_SHA = 0xC033; (*RFC5489*)(*RFC6347*)
  TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xC034; (*RFC5489*)
  TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035; (*RFC5489*)
  TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036; (*RFC5489*)
  TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037; (*RFC5489*)
  TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038; (*RFC5489*)
  TLS_ECDHE_PSK_WITH_NULL_SHA = 0xC039; (*RFC5489*)
  TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xC03A; (*RFC5489*)
  TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xC03B; (*RFC5489*)
  TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC03C; (*RFC6209*)
  TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC03D; (*RFC6209*)
  TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC03E; (*RFC6209*)
  TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC03F; (*RFC6209*)
  TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC040; (*RFC6209*)
  TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC041; (*RFC6209*)
  TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC042; (*RFC6209*)
  TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC043; (*RFC6209*)
  TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC044; (*RFC6209*)
  TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC045; (*RFC6209*)
  TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 0xC046; (*RFC6209*)
  TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 0xC047; (*RFC6209*)
  TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC048; (*RFC6209*)
  TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC049; (*RFC6209*)
  TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC04A; (*RFC6209*)
  TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC04B; (*RFC6209*)
  TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04C; (*RFC6209*)
  TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04D; (*RFC6209*)
  TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04E; (*RFC6209*)
  TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04F; (*RFC6209*)
  TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC050; (*RFC6209*)
  TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC051; (*RFC6209*)
  TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC052; (*RFC6209*)
  TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC053; (*RFC6209*)
  TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC054; (*RFC6209*)
  TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC055; (*RFC6209*)
  TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC056; (*RFC6209*)
  TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC057; (*RFC6209*)
  TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC058; (*RFC6209*)
  TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC059; (*RFC6209*)
  TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 0xC05A; (*RFC6209*)
  TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 0xC05B; (*RFC6209*)
  TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05C; (*RFC6209*)
  TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05D; (*RFC6209*)
  TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05E; (*RFC6209*)
  TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05F; (*RFC6209*)
  TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC060; (*RFC6209*)
  TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC061; (*RFC6209*)
  TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC062; (*RFC6209*)
  TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC063; (*RFC6209*)
  TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC064; (*RFC6209*)
  TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC065; (*RFC6209*)
  TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC066; (*RFC6209*)
  TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC067; (*RFC6209*)
  TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC068; (*RFC6209*)
  TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC069; (*RFC6209*)
  TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06A; (*RFC6209*)
  TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06B; (*RFC6209*)
  TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06C; (*RFC6209*)
  TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06D; (*RFC6209*)
  TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06E; (*RFC6209*)
  TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06F; (*RFC6209*)
  TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC070; (*RFC6209*)
  TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC071; (*RFC6209*)
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072; (*RFC6367*)
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073; (*RFC6367*)
  TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074; (*RFC6367*)
  TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075; (*RFC6367*)
  TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076; (*RFC6367*)
  TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077; (*RFC6367*)
  TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078; (*RFC6367*)
  TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079; (*RFC6367*)
  TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A; (*RFC6367*)
  TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B; (*RFC6367*)
  TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C; (*RFC6367*)
  TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D; (*RFC6367*)
  TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07E; (*RFC6367*)
  TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07F; (*RFC6367*)
  TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC080; (*RFC6367*)
  TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC081; (*RFC6367*)
  TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC082; (*RFC6367*)
  TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC083; (*RFC6367*)
  TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 0xC084; (*RFC6367*)
  TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 0xC085; (*RFC6367*)
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086; (*RFC6367*)
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087; (*RFC6367*)
  TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088; (*RFC6367*)
  TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089; (*RFC6367*)
  TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A; (*RFC6367*)
  TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B; (*RFC6367*)
  TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C; (*RFC6367*)
  TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D; (*RFC6367*)
  TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08E; (*RFC6367*)
  TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08F; (*RFC6367*)
  TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC090; (*RFC6367*)
  TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC091; (*RFC6367*)
  TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC092; (*RFC6367*)
  TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC093; (*RFC6367*)
  TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC094; (*RFC6367*)
  TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC095; (*RFC6367*)
  TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC096; (*RFC6367*)
  TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC097; (*RFC6367*)
  TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC098; (*RFC6367*)
  TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC099; (*RFC6367*)
  TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC09A; (*RFC6367*)
  TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC09B; (*RFC6367*)
  TLS_RSA_WITH_AES_128_CCM = 0xC09C; (*RFC6655*)
  TLS_RSA_WITH_AES_256_CCM = 0xC09D; (*RFC6655*)
  TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E; (*RFC6655*)
  TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F; (*RFC6655*)
  TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0; (*RFC6655*)
  TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1; (*RFC6655*)
  TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2; (*RFC6655*)
  TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3; (*RFC6655*)
  TLS_PSK_WITH_AES_128_CCM = 0xC0A4; (*RFC6655*)
  TLS_PSK_WITH_AES_256_CCM = 0xC0A5; (*RFC6655*)
  TLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6; (*RFC6655*)
  TLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7; (*RFC6655*)
  TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8; (*RFC6655*)
  TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9; (*RFC6655*)
  TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0xC0AA; (*RFC6655*)
  TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0xC0AB; (*RFC6655*)
} as uint16_t

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

let assemble_ciphersuite buf c =
  Cstruct.BE.set_uint16 buf 0 (ciphersuite_to_int c);
  Cstruct.shift buf 2

let get_ciphersuite buf = int_to_ciphersuite (Cstruct.BE.get_uint16 buf 0)

let get_ciphersuites buf =
  let rec go buf acc = function
    | 0 -> acc
    | n -> go (Cstruct.shift buf 2) ((get_ciphersuite buf) :: acc) (n - 1)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  let suites = go (Cstruct.shift buf 2) [] (len / 2) in
  (suites, len + 2)

cenum compression_method {
  NULL = 0
} as uint8_t

let assemble_compression_method buf c =
  Cstruct.set_uint8 buf 0 (compression_method_to_int c);
  Cstruct.shift buf 1

let get_compression_methods buf =
  let get_compression_method buf =
    match int_to_compression_method (Cstruct.get_uint8 buf 0) with
    | Some x -> x
  in
  let rec go buf acc = function
    | 0 -> acc
    | n -> go (Cstruct.shift buf 1) (get_compression_method buf :: acc) (n - 1)
  in
  let len = Cstruct.get_uint8 buf 0 in
  let methods = go (Cstruct.shift buf 1) [] len in
  (methods, len + 1)

(* from RFC 4366 *)
(* from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml *)
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

cenum max_fragment_length {
  TWO_9 = 1;
  TWO_10 = 2;
  TWO_11 = 3;
  TWO_12 = 4
} as uint8_t

cenum ec_curve_type {
  EXPLICIT_PRIME = 1;
  EXPLICIT_CHAR2 = 2;
  NAMED_CURVE = 3
} as uint8_t

cenum named_curve {
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

cenum ec_point_format {
  UNCOMPRESSED = 0;
  ANSIX962_COMPRESSED_PRIME = 1;
  ANSIX962_COMPRESSED_CHAR2 = 2;
  (* reserved 248..255 *)
} as uint8_t

type extension =
  | Hostname of string list
  | MaxFragmentLength of max_fragment_length option
  | EllipticCurves of (named_curve option) list
  | ECPointFormats of (ec_point_format option) list
  | Unsupported of extension_type

(*
let assemble_extension buf = function
  | Hostname hosts -> assemble_hostname buf hosts
  | MaxFragmentLength mfl -> assemble_max_fragment_length buf mfl
  | EllipticCurves curves -> assemble_elliptic_curves buf curves
  | ECPointFormats formats -> assemble_ecpoint_formats formats
 *)

let extension_to_string = function
  | Hostname hosts -> "Hostnames: " ^ (String.concat ", " hosts)
  | MaxFragmentLength mfl -> (match mfl with
                              | None -> "unknown max_fragment_length"
                              | Some x -> "Maximum fragment length: " ^ (max_fragment_length_to_string x))
  | EllipticCurves curves -> "Elliptic curves: " ^
                               (String.concat ", " (List.map (function
                                                               | None -> ""
                                                               | Some e -> named_curve_to_string e) curves))
  | ECPointFormats formats -> "Elliptic Curve formats: " ^ (String.concat ", " (List.map (function
                                                             | None -> ""
                                                             | Some f -> ec_point_format_to_string f) formats))
  | Unsupported i -> "unsupported: " ^ (extension_type_to_string i)

let get_hostnames buf =
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
  in
  go (Cstruct.sub buf 2 list_length) []

let get_fragment_length buf =
  int_to_max_fragment_length (Cstruct.get_uint8 buf 0)

let get_elliptic_curves buf =
  let rec go buf acc = match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let curve = int_to_named_curve (Cstruct.BE.get_uint16 buf 0) in
       go (Cstruct.shift buf 2) (curve :: acc)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  go (Cstruct.sub buf 2 len) []

let get_ec_point_format buf =
  let rec go buf acc = match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let fmt = int_to_ec_point_format (Cstruct.get_uint8 buf 0) in
       go (Cstruct.shift buf 1) (fmt :: acc)
  in
  let len = Cstruct.get_uint8 buf 0 in
  go (Cstruct.sub buf 1 len) []

let get_extension buf =
  let etype = Cstruct.BE.get_uint16 buf 0 in
  let len = Cstruct.BE.get_uint16 buf 2 in
  let buf = Cstruct.sub buf 4 len in
  let data = match (int_to_extension_type etype) with
    | Some SERVER_NAME -> Hostname (get_hostnames buf)
    | Some MAX_FRAGMENT_LENGTH -> MaxFragmentLength (get_fragment_length buf)
    | Some ELLIPTIC_CURVES -> EllipticCurves (get_elliptic_curves buf)
    | Some EC_POINT_FORMATS -> ECPointFormats (get_ec_point_format buf)
    | Some x -> Unsupported x
  in
  (data, 4 + len)

let get_extensions buf =
  let rec go buf acc =
    match (Cstruct.len buf) with
    | 0 -> acc
    | n ->
       let extension, esize = get_extension buf in
       go (Cstruct.shift buf esize) (extension :: acc)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  (go (Cstruct.sub buf 2 len) [], Cstruct.shift buf (2 + len))

cstruct c_hello {
  uint8_t major_version;
  uint8_t minor_version;
  uint32_t gmt_unix_time;
  uint8_t  random[28];
} as big_endian

type 'a hello = {
  major  : int;
  minor  : int;
  time   : uint32;
  random : Cstruct.t;
  sessionid : Cstruct.t option;
  ciphersuites : 'a;
  compression_methods : compression_method list;
  extensions : extension list
}

type client_hello = ciphersuite option list hello
type server_hello = ciphersuite option hello

let client_hello_to_string c_h =
  sprintf "client hello: protocol %d.%d ciphers %s extensions %s"
          c_h.major c_h.minor
          (List.map (function
                      | None -> ""
                      | Some x -> ciphersuite_to_string x)
                     c_h.ciphersuites
           |> String.concat ", ")
          (List.map extension_to_string c_h.extensions |> String.concat ", ")

let server_hello_to_string c_h =
  sprintf "server hello: protocol %d.%d cipher %s extensions %s"
          c_h.major c_h.minor
          (match c_h.ciphersuites with
           | None -> "unknown"
           | Some x -> ciphersuite_to_string x)
          (List.map extension_to_string c_h.extensions |> String.concat ", ")

let assemble_client_hello cl buf =
  Cstruct.set_uint8 buf 0 cl.major;
  Cstruct.set_uint8 buf 1 cl.minor;
  Cstruct.BE.set_uint32 buf 2 cl.time;
  Cstruct.blit cl.random 0 buf 6 28;
  let buf = Cstruct.shift buf 34 in
  let buf = match cl.sessionid with
    | None ->
       Cstruct.set_uint8 buf 0 0;
       Cstruct.shift buf 1
    | Some s ->
       let slen = Cstruct.len s in
       Cstruct.set_uint8 buf 0 slen;
       Cstruct.blit s 0 buf 1 slen;
       Cstruct.shift buf (slen + 1)
  in
  Cstruct.BE.set_uint16 buf 0 (2 * List.length cl.ciphersuites);
  let buf = Cstruct.shift buf 2 in
  let marshaln f buf values =
    List.fold_left f buf values
  in
  marshaln assemble_ciphersuite buf cl.ciphersuites;
  Cstruct.set_uint8 buf 0 (List.length cl.compression_methods);
  let buf = Cstruct.shift buf 1 in
  marshaln assemble_compression_method buf cl.compression_methods;
  Cstruct.BE.set_uint16 buf 0 (List.length cl.extensions)
(*  let buf = Cstruct.shift buf 2 in
  List.iter (assemble_extension buf) cl.extensions *)

let parse_client_hello buf =
  let major = get_c_hello_major_version buf in
  let minor = get_c_hello_minor_version buf in
  let time = get_c_hello_gmt_unix_time buf in
  let random = get_c_hello_random buf in
  let sessionid, slen = get_varlength (Cstruct.shift buf 34) 1 in
  let ciphersuites, clen = get_ciphersuites (Cstruct.shift buf (34 + slen)) in
  let compression_methods, dlen = get_compression_methods (Cstruct.shift buf (34 + slen + clen)) in
  let extensions, elen = get_extensions (Cstruct.shift buf (34 + slen + clen + dlen)) in
  (* assert that dlen is small *)
  { major; minor; time; random; sessionid; ciphersuites; compression_methods; extensions }

let parse_server_hello buf =
  let major = get_c_hello_major_version buf in
  let minor = get_c_hello_minor_version buf in
  let time = get_c_hello_gmt_unix_time buf in
  let random = get_c_hello_random buf in
  let sessionid, slen = get_varlength (Cstruct.shift buf 34) 1 in
  let ciphersuites = get_ciphersuite (Cstruct.shift buf (34 + slen)) in
  let compression_methods, dlen = get_compression_methods (Cstruct.shift buf (34 + slen + 2)) in
  let extensions, elen = get_extensions (Cstruct.shift buf (34 + slen + 2 + dlen)) in
  (* assert that dlen is small *)
  { major; minor; time; random; sessionid; ciphersuites; compression_methods; extensions }

let get_certificate buf =
  let len = get_uint24_len buf in
  ((Cstruct.sub buf 3 len), len + 3)

let get_certificates buf =
  let rec go buf acc =
            match (Cstruct.len buf) with
            | 0 -> acc
            | n -> let cert, size = get_certificate buf in
                   go (Cstruct.shift buf size) (cert :: acc)
  in
  let len = get_uint24_len buf in
  go (Cstruct.sub buf 3 len) []

type rsa_parameters = {
  rsa_modulus : Cstruct.t;
  rsa_exponent : Cstruct.t;
}

let rsa_param_to_string r =
  "RSA parameters: modulus: " ^ Cstruct.copy r.rsa_modulus 0 (Cstruct.len r.rsa_modulus) ^
  "exponent: " ^ Cstruct.copy r.rsa_exponent 0 (Cstruct.len r.rsa_exponent)

let parse_rsa_parameters buf =
  let mlength = Cstruct.BE.get_uint16 buf 0 in
  let rsa_modulus = Cstruct.sub buf 2 mlength in
  let buf = Cstruct.shift buf (2 + mlength) in
  let elength = Cstruct.BE.get_uint16 buf 0 in
  let rsa_exponent = Cstruct.sub buf 2 elength in
  ({ rsa_modulus ; rsa_exponent }, 4 + mlength + elength)

type dsa_parameters = {
  dh_p : Cstruct.t;
  dh_g : Cstruct.t;
  dh_Ys : Cstruct.t;
}

let parse_dsa_parameters buf =
  let plength = Cstruct.BE.get_uint16 buf 0 in
  let dh_p = Cstruct.sub buf 2 plength in
  let buf = Cstruct.shift buf (2 + plength) in
  let glength = Cstruct.BE.get_uint16 buf 0 in
  let dh_g = Cstruct.sub buf 2 glength in
  let buf = Cstruct.shift buf (2 + plength) in
  let yslength = Cstruct.BE.get_uint16 buf 0 in
  let dh_Ys = Cstruct.sub buf 2 yslength in
  ({ dh_p ; dh_g; dh_Ys }, 6 + plength + glength + yslength)

let dsa_param_to_string r =
  "DSA parameters: p: " ^ Cstruct.copy r.dh_p 0 (Cstruct.len r.dh_p) ^
  "g: " ^ Cstruct.copy r.dh_g 0 (Cstruct.len r.dh_g) ^
  "Ys: " ^ Cstruct.copy r.dh_Ys 0 (Cstruct.len r.dh_Ys)

type signature =
  | Anonymous
  | RSA of Cstruct.t
  | DSA of Cstruct.t

let sig_to_string = function
  | Anonymous -> "anonymous"
  | RSA r -> "RSA sig: " ^ Cstruct.copy r 0 (Cstruct.len r)
  | DSA d -> "DSA sig: " ^ Cstruct.copy d 0 (Cstruct.len d)

let parse_sig buf =
  let len = Cstruct.BE.get_uint16 buf 0 in
  Cstruct.sub buf 2 len

type server_key_exchange =
  | DiffieHellmann of dsa_parameters * signature
  | Rsa of rsa_parameters * signature

let parse_server_key_exchange buf =
  let len = Cstruct.BE.get_uint16 buf 0 in
  let buf = Cstruct.sub buf 2 len in
  let dh, size = parse_dsa_parameters buf in
  let sign = DSA (parse_sig (Cstruct.shift buf size)) in
  DiffieHellmann (dh, sign)

let server_key_exchange_to_string = function
  | DiffieHellmann (param, s)-> dsa_param_to_string param ^ sig_to_string s
  | Rsa (param, s) -> rsa_param_to_string param ^ sig_to_string s

type tls_handshake =
  | HelloRequest
  | ClientHello of client_hello
  | ServerHello of server_hello
  | Certificate of Cstruct.t list
  | ServerKeyExchange of server_key_exchange

let handshake_to_string = function
  | HelloRequest -> "Hello request"
  | ClientHello x -> client_hello_to_string x
  | ServerHello x -> server_hello_to_string x
  | Certificate x -> sprintf "Certificate: %d" (List.length x)
  | ServerKeyExchange x -> server_key_exchange_to_string x

let parse_handshake buf =
  let handshake_type = int_to_handshake_type (get_handshake_handshake_type buf) in
  let len = get_uint24_len (Cstruct.shift buf 1) in
  let payload = Cstruct.sub buf 4 len in
  let data = match handshake_type with
    | Some HELLO_REQUEST -> HelloRequest
    | Some CLIENT_HELLO -> ClientHello (parse_client_hello payload)
    | Some SERVER_HELLO -> ServerHello (parse_server_hello payload)
    | Some CERTIFICATE -> Certificate (get_certificates payload)
  in ( data, Cstruct.shift buf (4 + len) )

(*type tls_alert = {
}
type tls_application_data = {
}
type tls_change_ciper_spec = {
}
 *)
type tls_body =
(*  | Tls_change_cipher_spec of tls_change_cipher_spec
  | Tls_application_data of tls_application_data
  | Tls_alert of tls_alert *)
  | Tls_handshake of tls_handshake

let parse buf =
  let header, buf = parse_hdr buf in
  let body, buf = match header.content_type with
    | HANDSHAKE          -> parse_handshake buf
  in (header, body, buf)

let header_to_string (header : tls_hdr) =
  sprintf "protocol %d.%d: %s" header.major header.minor (content_type_to_string header.content_type)
