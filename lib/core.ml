(** Core type definitions *)

open Sexplib.Conv
open Nocrypto

open Packet
open Ciphersuite

type tls_version =
  | TLS_1_0
  | TLS_1_1
  | TLS_1_2
  with sexp

let pair_of_tls_version = function
  | TLS_1_0   -> (3, 1)
  | TLS_1_1   -> (3, 2)
  | TLS_1_2   -> (3, 3)

let tls_version_of_pair = function
  | (3, 1) -> Some TLS_1_0
  | (3, 2) -> Some TLS_1_1
  | (3, 3) -> Some TLS_1_2
  | _      -> None

type tls_any_version =
  | SSL_3
  | Supported of tls_version
  | TLS_1_X of int
  with sexp

let any_version_to_version = function
  | Supported v -> Some v
  | _           -> None

let version_eq a b =
  match a with
  | Supported x -> x = b
  | _           -> false

let version_ge a b =
  match a with
  | Supported x -> x >= b
  | SSL_3       -> false
  | TLS_1_X _   -> true

let tls_any_version_of_pair x =
  match tls_version_of_pair x with
  | Some v -> Some (Supported v)
  | None ->
     match x with
     | (3, 0) -> Some SSL_3
     | (3, x) -> Some (TLS_1_X x)
     | _      -> None

let pair_of_tls_any_version = function
  | Supported x -> pair_of_tls_version x
  | SSL_3       -> (3, 0)
  | TLS_1_X m   -> (3, m)

let max_protocol_version (_, hi) = hi
let min_protocol_version (lo, _) = lo

type tls_hdr = {
  content_type : content_type;
  version      : tls_any_version;
} with sexp

type extension =
  | Hostname of string option
  | MaxFragmentLength of max_fragment_length
  | EllipticCurves of named_curve_type list
  | ECPointFormats of ec_point_format list
  | SecureRenegotiation of Cstruct.t
  | Padding of int
  | SignatureAlgorithms of (Hash.hash * signature_algorithm_type) list
  | UnknownExtension of (int * Cstruct.t)
  with sexp

type ('a, 'b) hello = {
  version      : 'b;
  random       : Cstruct.t;
  sessionid    : Cstruct.t option;
  ciphersuites : 'a;
  extensions   : extension list
} with sexp

type client_hello = (any_ciphersuite list, tls_any_version) hello
  with sexp

type server_hello = (ciphersuite, tls_version) hello
  with sexp

type rsa_parameters = {
  rsa_modulus  : Cstruct.t;
  rsa_exponent : Cstruct.t;
} with sexp

type dh_parameters = {
  dh_p  : Cstruct.t;
  dh_g  : Cstruct.t;
  dh_Ys : Cstruct.t;
} with sexp

type ec_curve = {
  a : Cstruct.t;
  b : Cstruct.t
} with sexp

type ec_prime_parameters = {
  prime    : Cstruct.t;
  curve    : ec_curve;
  base     : Cstruct.t;
  order    : Cstruct.t;
  cofactor : Cstruct.t;
  public   : Cstruct.t
} with sexp

type ec_char_parameters = {
  m        : int;
  basis    : ec_basis_type;
  ks       : Cstruct.t list;
  curve    : ec_curve;
  base     : Cstruct.t;
  order    : Cstruct.t;
  cofactor : Cstruct.t;
  public   : Cstruct.t
} with sexp

type ec_parameters =
  | ExplicitPrimeParameters of ec_prime_parameters
  | ExplicitCharParameters of ec_char_parameters
  | NamedCurveParameters of (named_curve_type * Cstruct.t)
  with sexp

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
  with sexp

type tls_alert = alert_level * alert_type
  with sexp

type tls_body =
  | TLS_ChangeCipherSpec
  | TLS_ApplicationData
  | TLS_Alert of tls_alert
  | TLS_Handshake of tls_handshake
  with sexp

(** the master secret of a TLS connection *)
type master_secret = Cstruct.t with sexp

(** information about an open session *)
type epoch_data = {
  protocol_version : tls_version ;
  ciphersuite      : Ciphersuite.ciphersuite ;
  peer_certificate : X509.t list ;
  peer_name        : string option ;
  trust_anchor     : X509.t option ;
  own_certificate  : X509.t list ;
  own_private_key  : Nocrypto.Rsa.priv option ;
  own_name         : string option ;
  master_secret    : master_secret ;
} with sexp
