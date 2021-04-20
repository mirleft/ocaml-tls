
type error =
  | TrailingBytes  of string
  | WrongLength    of string
  | Unknown        of string
  | Underflow
  | Overflow       of int
  | UnknownVersion of (int * int)
  | UnknownContent of int [@@deriving sexp_of]

val parse_version     : Cstruct.t -> (Core.tls_version, error) result
val parse_any_version : Cstruct.t -> (Core.tls_any_version, error) result
val parse_record      : Cstruct.t ->
  ([ `Record of (Core.tls_hdr * Cstruct.t) * Cstruct.t
   | `Fragment of Cstruct.t
   ], error) result

val parse_handshake_frame : Cstruct.t -> (Cstruct.t option * Cstruct.t)
val parse_handshake : Cstruct.t -> (Core.tls_handshake, error) result

val parse_alert     : Cstruct.t -> (Core.tls_alert, error) result

val parse_change_cipher_spec   : Cstruct.t -> (unit, error) result

val parse_certificate_request     : Cstruct.t -> (Packet.client_certificate_type list * Cstruct.t list, error) result
val parse_certificate_request_1_2 : Cstruct.t -> (Packet.client_certificate_type list * Core.signature_algorithm list * Cstruct.t list, error) result
val parse_certificate_request_1_3 : Cstruct.t -> (Cstruct.t option * Core.certificate_request_extension list, error) result

val parse_certificates : Cstruct.t -> (Cstruct.t list, error) result
val parse_certificates_1_3 : Cstruct.t -> (Cstruct.t * (Cstruct.t * 'a list) list, error) result

val parse_client_dh_key_exchange : Cstruct.t -> (Cstruct.t, error) result
val parse_client_ec_key_exchange : Cstruct.t -> (Cstruct.t, error) result

val parse_dh_parameters        : Cstruct.t -> (Core.dh_parameters * Cstruct.t * Cstruct.t, error) result
val parse_ec_parameters        : Cstruct.t -> ([ `X25519 | `P256 | `P384 | `P521 ] * Cstruct.t * Cstruct.t * Cstruct.t, error) result
val parse_digitally_signed     : Cstruct.t -> (Cstruct.t, error) result
val parse_digitally_signed_1_2 : Cstruct.t -> (Core.signature_algorithm * Cstruct.t, error) result
