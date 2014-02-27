open Core
open Printf
open Packet

let header_to_string (header : tls_hdr) =
  let (major, minor) = header.version in
  sprintf "protocol %d.%d: %s"
          major minor (content_type_to_string header.content_type)

let certificate_request_to_string cr =
  "FOOO"

let extension_to_string = function
  | Hostname hosts -> "Hostnames: " ^ (String.concat ", " hosts)
  | MaxFragmentLength mfl -> (match mfl with
                              | None -> "unknown max_fragment_length"
                              | Some x -> "Maximum fragment length: " ^ (max_fragment_length_to_string x))
  | EllipticCurves curves -> "Elliptic curves: " ^
                               (String.concat ", " (List.map named_curve_type_to_string curves))
  | ECPointFormats formats -> "Elliptic Curve formats: " ^ (String.concat ", " (List.map ec_point_format_to_string formats))
  | Unsupported i -> "unsupported: " ^ (extension_type_to_string i)

let client_hello_to_string c_h =
  let (major, minor) = c_h.version in
  sprintf "client hello: protocol %d.%d\n  ciphers %s\n  extensions %s"
          major minor
          (List.map Ciphersuite.ciphersuite_to_string c_h.ciphersuites |> String.concat ", ")
          (List.map extension_to_string c_h.extensions |> String.concat ", ")

let server_hello_to_string (c_h : server_hello) =
  let (major, minor) = c_h.version in
  sprintf "server hello: protocol %d.%d cipher %s extensions %s"
          major minor
          (Ciphersuite.ciphersuite_to_string c_h.ciphersuites)
          (List.map extension_to_string c_h.extensions |> String.concat ", ")

let rsa_param_to_string r =
  "RSA parameters: modulus: " ^ Cstruct.copy r.rsa_modulus 0 (Cstruct.len r.rsa_modulus) ^
  "exponent: " ^ Cstruct.copy r.rsa_exponent 0 (Cstruct.len r.rsa_exponent)

let dsa_param_to_string r =
  "DSA parameters: p: " ^ Cstruct.copy r.dh_p 0 (Cstruct.len r.dh_p) ^
  "g: " ^ Cstruct.copy r.dh_g 0 (Cstruct.len r.dh_g) ^
  "Ys: " ^ Cstruct.copy r.dh_Ys 0 (Cstruct.len r.dh_Ys)

let ec_prime_parameters_to_string pp = "EC Prime Parameters"

let ec_char_parameters_to_string cp = "EC Char Parameters"

let ec_param_to_string = function
  | ExplicitPrimeParameters pp -> ec_prime_parameters_to_string pp
  | ExplicitCharParameters cp -> ec_char_parameters_to_string cp
  | NamedCurveParameters (nc, public) -> named_curve_type_to_string nc

let server_key_exchange_to_string = function
  | DiffieHellman (param, s)-> "DH Server KEX"
  | Rsa (param, s) -> "RSA Server KEX"
  | EllipticCurve (param, s) -> "EC Server KEX"

let handshake_to_string = function
  | HelloRequest -> "Hello request"
  | ServerHelloDone -> "Server hello done"
  | ClientHello x -> client_hello_to_string x
  | ServerHello x -> server_hello_to_string x
  | Certificate x -> sprintf "Certificate: %d" (List.length x)
  | ServerKeyExchange x -> server_key_exchange_to_string x
  | ClientKeyExchange x -> sprintf "Client KEX: %d" (Cstruct.len x)
  | CertificateRequest x -> certificate_request_to_string x
  | Finished x -> "Finished"

let alert_to_string (lvl, typ) =
  alert_level_to_string lvl ^ " " ^ alert_type_to_string typ

let body_to_string = function
  | TLS_ChangeCipherSpec -> "TLS Change Cipher Spec"
  | TLS_ApplicationData -> "TLS Application Data"
  | TLS_Handshake x -> handshake_to_string x
  | TLS_Alert a -> alert_to_string a

let to_string (hdr, body) =
  sprintf "header: %s\n body: %s" (header_to_string hdr) (body_to_string body)
