
type error =
  | Overflow

module Or_error :
  Control.Or_error with type err = error

val parse_version   : Cstruct.t -> Core.tls_version Or_error.or_error
val parse_hdr       : Cstruct.t -> Packet.content_type option * Core.tls_version option * int

val parse_handshake : Cstruct.t -> Core.tls_handshake Or_error.or_error

val parse_alert     : Cstruct.t -> Core.tls_alert Or_error.or_error

val parse_dh_parameters : Cstruct.t -> (Core.dh_parameters * Cstruct.t * Cstruct.t) Or_error.or_error
val parse_digitally_signed : Cstruct.t -> Cstruct.t Or_error.or_error
val parse_digitally_signed_1_2 : Cstruct.t -> (Ciphersuite.hash_algorithm * Packet.signature_algorithm_type * Cstruct.t) Or_error.or_error
