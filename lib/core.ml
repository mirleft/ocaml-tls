open Packet
open Ciphersuite

let o f g x = f (g x)

let (<>) = Utils.cs_append

type tls_version =
  | SSL_3
  | TLS_1_0
  | TLS_1_1
  | TLS_1_2

let pair_of_tls_version = function
  | TLS_1_0 -> (3, 1)
  | TLS_1_1 -> (3, 2)
  | TLS_1_2 -> (3, 3)

let tls_version_of_pair = function
  | (3, 0) -> Some SSL_3
  | (3, 1) -> Some TLS_1_0
  | (3, 2) -> Some TLS_1_1
  | (3, 3) -> Some TLS_1_2
  | _      -> None

type tls_hdr = {
  content_type : content_type;
  version      : tls_version;
}

type extension =
  | Hostname of string option
  | MaxFragmentLength of max_fragment_length
  | EllipticCurves of named_curve_type list
  | ECPointFormats of ec_point_format list
  | SecureRenegotiation of Cstruct.t
  | Padding of int
  | UnknownExtension of (int * Cstruct.t)

type 'a hello = {
  version      : tls_version;
  random       : Cstruct.t;
  sessionid    : Cstruct.t option;
  ciphersuites : 'a;
  extensions   : extension list
}

type client_hello = ciphersuite list hello
type server_hello = ciphersuite hello

type rsa_parameters = {
  rsa_modulus : Cstruct.t;
  rsa_exponent : Cstruct.t;
}

type dh_parameters = {
  dh_p : Cstruct.t;
  dh_g : Cstruct.t;
  dh_Ys : Cstruct.t;
}

type ec_curve = {
  a : Cstruct.t;
  b : Cstruct.t
}

type ec_prime_parameters = {
  prime : Cstruct.t;
  curve : ec_curve;
  base : Cstruct.t;
  order : Cstruct.t;
  cofactor : Cstruct.t;
  public : Cstruct.t
}

type ec_char_parameters = {
  m : int;
  basis : ec_basis_type;
  ks : Cstruct.t list;
  curve : ec_curve;
  base : Cstruct.t;
  order : Cstruct.t;
  cofactor : Cstruct.t;
  public : Cstruct.t
}

type ec_parameters =
  | ExplicitPrimeParameters of ec_prime_parameters
  | ExplicitCharParameters of ec_char_parameters
  | NamedCurveParameters of (named_curve_type * Cstruct.t)

type certificate_request = {
  certificate_types       : client_certificate_type list;
  certificate_authorities : string list
}

type tls_handshake =
  | HelloRequest
  | ServerHelloDone
  | ClientHello of client_hello
  | ServerHello of server_hello
  | Certificate of Cstruct.t list
  | ServerKeyExchange of Cstruct.t
  | CertificateRequest of certificate_request
  | ClientKeyExchange of Cstruct.t
  | Finished of Cstruct.t

type tls_alert = alert_level * alert_type

type tls_body =
  | TLS_ChangeCipherSpec
  | TLS_ApplicationData
  | TLS_Alert of tls_alert
  | TLS_Handshake of tls_handshake
