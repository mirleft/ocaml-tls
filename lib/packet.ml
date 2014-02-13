(* RFC 2246 *)

open Printf
open Cstruct

cenum content_type {
  CHANGE_CIPHER_SPEC = 20;
  ALERT              = 21;
  HANDSHAKE          = 22;
  APPLICATION_DATA   = 23
} as uint8_t

cstruct tls_h {
  uint8_t  content_type;
  uint8_t  major_version;
  uint8_t  minor_version;
  uint16_t length
} as big_endian

type tls_hdr = {
  content_type : content_type option;
  major        : int;
  minor        : int
}

let parse_hdr buf =
  let content_type = int_to_content_type (get_tls_h_content_type buf) in
  let major = get_tls_h_major_version buf in
  let minor = get_tls_h_minor_version buf in
  let len = get_tls_h_length buf in
  let payload = Cstruct.sub buf 5 len in
  ( { content_type; major; minor }, payload)

cenum handshake_type {
  HELLO_REQUEST       = 0;
  CLIENT_HELLO        = 1;
  SERVER_HELLO        = 2;
  CERTIFICATE         = 11;
  SERVER_KEY_EXCHANGE = 12;
  CERTIFICATE_REQUEST = 13;
  SERVER_HELLO_DONE   = 14;
  CERTIFICATE_VERIFY  = 15;
  CLIENT_KEY_EXCHANGE = 16;
  FINISHED            = 20
} as uint8_t

cstruct handshake {
  uint8_t handshake_type;
  uint16_t handshake_length; (* HACK: 24 bits type not in cstruct *)
  uint8_t handshake_length2
} as big_endian

let rec pow a = function
  | 0 -> 1
  | 1 -> a
  | n -> let b = pow a (n / 2) in
         b * b * (if n mod 2 = 0 then 1 else a)


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

  (* from RFC 5246 *)
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = 0x003E;
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = 0x003F;
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = 0x0040;
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = 0x0067;
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = 0x0068;
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = 0x0069;
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = 0x006A;
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = 0x006B;

  TLS_DH_anon_WITH_AES_128_CBC_SHA256   = 0x006C;
  TLS_DH_anon_WITH_AES_256_CBC_SHA256   = 0x006D;
} as uint16_t


let get_ciphersuites buf =
  let rec go buf acc = function
    | 0 -> acc
    | n -> go (Cstruct.shift buf 2) ((int_to_ciphersuite (Cstruct.BE.get_uint16 buf 0)) :: acc) (n - 1)
  in
  let len = Cstruct.BE.get_uint16 buf 0 in
  let suites = go (Cstruct.shift buf 2) [] (len / 2) in
  (suites, len + 2)

cenum compression_method {
  Null = 0
} as uint8_t

let get_compression_methods buf =
  let rec go buf acc = function
    | 0 -> acc
    | n -> go (Cstruct.shift buf 1) ((int_to_compression_method (Cstruct.get_uint8 buf 0)) :: acc) (n - 1)
  in
  let len = Cstruct.get_uint8 buf 0 in
  let methods = go (Cstruct.shift buf 1) [] len in
  (methods, len + 1)

cstruct c_hello {
  uint8_t major_version;
  uint8_t minor_version;
  uint32_t gmt_unix_time;
  uint8_t  random[28];
} as big_endian

type client_hello = {
  major  : int;
  minor  : int;
  time   : uint32;
  random : Cstruct.t;
  sessionid : Cstruct.t option;
  ciphersuites : (ciphersuite option) list;
  compression_methods : (compression_method option) list
}

let hello_to_string c_h =
  sprintf "client hello %d %d ciphers %s" c_h.major c_h.minor
          ((List.map (fun s -> match s with
                              | None -> ""
                              | Some x -> ciphersuite_to_string x) c_h.ciphersuites)
           |> String.concat ",")

let parse_client_hello buf =
  let major = get_c_hello_major_version buf in
  let minor = get_c_hello_minor_version buf in
  let time = get_c_hello_gmt_unix_time buf in
  let random = get_c_hello_random buf in
  let sessionid, slen = get_varlength (Cstruct.shift buf 34) 1 in
  let ciphersuites, clen = get_ciphersuites (Cstruct.shift buf (34 + slen)) in
  let compression_methods, dlen = get_compression_methods (Cstruct.shift buf (34 + slen + clen)) in
  (* assert that dlen is small *)
  { major; minor; time; random; sessionid; ciphersuites; compression_methods }

type tls_handshake =
  | Client_hello of client_hello

let handshake_to_string = function
 | Client_hello x -> hello_to_string x

let parse_handshake buf =
  let handshake_type = int_to_handshake_type (get_handshake_handshake_type buf) in
  let len = (get_handshake_handshake_length buf) * (pow 2 8) + (get_handshake_handshake_length2 buf) in
  let payload = Cstruct.sub buf 4 len in
  let data = match handshake_type with
    | Some CLIENT_HELLO -> Client_hello (parse_client_hello payload)
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
  let header, buf' = parse_hdr buf in
  let body, buf'' = match header.content_type with
    | Some HANDSHAKE          -> parse_handshake buf'
  in (header, body, buf'')

let header_to_string header =
  sprintf "%s %d.%d" (match header.content_type with
                      | None -> "unknown"
                      | Some x -> content_type_to_string x) header.major header.minor
