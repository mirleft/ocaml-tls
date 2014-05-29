
type error =
  | TrailingBytes of string
  | WrongLength   of string
  | Unknown       of string
  | Underflow

module Or_error :
  Control.Or_error with type err = error
open Or_error

val parse_version   : Cstruct.t -> Core.tls_version or_error
val parse_hdr       : Cstruct.t -> Packet.content_type option * Core.tls_version option * int

val parse_handshake : Cstruct.t -> (Core.tls_handshake * Cstruct.t * Cstruct.t) or_error

val parse_alert     : Cstruct.t -> Core.tls_alert or_error

val parse_dh_parameters : Cstruct.t -> (Core.dh_parameters * Cstruct.t * Cstruct.t) or_error
val parse_digitally_signed : Cstruct.t -> Cstruct.t or_error
val parse_digitally_signed_1_2 : Cstruct.t -> (Ciphersuite.hash_algorithm * Packet.signature_algorithm_type * Cstruct.t) or_error
