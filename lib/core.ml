open Sexplib.Conv

open Packet
open Ciphersuite

(* Monadic control-flow core. *)
include Control.Or_error_make (struct type err = Packet.alert_type end)

(* Monadically rewraps the real (effectful) tracing to ease out transition to
 * actual monadic tracer. *)
module Trace = struct
  let item id x = ( Tracing.item id x ; return () )
end

module Cstruct_with_sexp = struct
  type t = Cstruct.t
  let t_of_sexp _ = assert false
  let sexp_of_t _ = assert false
end

type tls_version =
  | SSL_3
  | TLS_1_0
  | TLS_1_1
  | TLS_1_2
  | TLS_1_X of (int * int)
  with sexp

(* this is partial. it is intentional that we have no case for SSL3 *)
let pair_of_tls_version = function
  | TLS_1_0   -> (3, 1)
  | TLS_1_1   -> (3, 2)
  | TLS_1_2   -> (3, 3)
  | TLS_1_X x -> x

let tls_version_of_pair = function
  | (3, 0) -> Some SSL_3
  | (3, 1) -> Some TLS_1_0
  | (3, 2) -> Some TLS_1_1
  | (3, 3) -> Some TLS_1_2
  | (3, x) -> Some (TLS_1_X (3, x))
  | _      -> None

let max_protocol_version (hi, _) = hi
let min_protocol_version (_, lo) = lo

type tls_hdr = {
  content_type : content_type;
  version      : tls_version;
} with sexp

type extension =
  | Hostname of string option
  | MaxFragmentLength of max_fragment_length
  | EllipticCurves of named_curve_type list
  | ECPointFormats of ec_point_format list
  | SecureRenegotiation of Cstruct_with_sexp.t
  | Padding of int
  | SignatureAlgorithms of (hash_algorithm * signature_algorithm_type) list
  | UnknownExtension of (int * Cstruct_with_sexp.t)
  with sexp

type 'a hello = {
  version      : tls_version;
  random       : Cstruct_with_sexp.t;
  sessionid    : Cstruct_with_sexp.t option;
  ciphersuites : 'a;
  extensions   : extension list
} with sexp

type client_hello = ciphersuite list hello
  with sexp

type server_hello = ciphersuite hello
  with sexp

type rsa_parameters = {
  rsa_modulus  : Cstruct_with_sexp.t;
  rsa_exponent : Cstruct_with_sexp.t;
} with sexp

type dh_parameters = {
  dh_p  : Cstruct_with_sexp.t;
  dh_g  : Cstruct_with_sexp.t;
  dh_Ys : Cstruct_with_sexp.t;
} with sexp

type ec_curve = {
  a : Cstruct_with_sexp.t;
  b : Cstruct_with_sexp.t
} with sexp

type ec_prime_parameters = {
  prime    : Cstruct_with_sexp.t;
  curve    : ec_curve;
  base     : Cstruct_with_sexp.t;
  order    : Cstruct_with_sexp.t;
  cofactor : Cstruct_with_sexp.t;
  public   : Cstruct_with_sexp.t
} with sexp

type ec_char_parameters = {
  m        : int;
  basis    : ec_basis_type;
  ks       : Cstruct_with_sexp.t list;
  curve    : ec_curve;
  base     : Cstruct_with_sexp.t;
  order    : Cstruct_with_sexp.t;
  cofactor : Cstruct_with_sexp.t;
  public   : Cstruct_with_sexp.t
} with sexp

type ec_parameters =
  | ExplicitPrimeParameters of ec_prime_parameters
  | ExplicitCharParameters of ec_char_parameters
  | NamedCurveParameters of (named_curve_type * Cstruct_with_sexp.t)
  with sexp

type certificate_request = {
  certificate_types       : client_certificate_type list;
  certificate_authorities : string list
} with sexp

type tls_handshake =
  | HelloRequest
  | ServerHelloDone
  | ClientHello of client_hello
  | ServerHello of server_hello
  | Certificate of Cstruct_with_sexp.t list
  | ServerKeyExchange of Cstruct_with_sexp.t
  | CertificateRequest of certificate_request
  | ClientKeyExchange of Cstruct_with_sexp.t
  | Finished of Cstruct_with_sexp.t
  with sexp

type tls_alert = alert_level * alert_type
  with sexp

type tls_body =
  | TLS_ChangeCipherSpec
  | TLS_ApplicationData
  | TLS_Alert of tls_alert
  | TLS_Handshake of tls_handshake
  with sexp
