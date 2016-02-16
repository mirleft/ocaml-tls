
type error =
  | TrailingBytes  of string
  | WrongLength    of string
  | Unknown        of string
  | Underflow
  | Overflow       of int
  | UnknownVersion of (int * int)
  | UnknownContent of int
with sexp

module Or_error :
  Control.Or_error with type err = error and type 'a t = ('a, error) Control.result

val parse_version     : Cstruct.t -> Core.tls_version Or_error.t
val parse_any_version : Cstruct.t -> Core.tls_any_version Or_error.t
val parse_record      : Cstruct.t ->
  [ `Record of (Core.tls_hdr * Cstruct.t) * Cstruct.t
  | `Fragment of Cstruct.t
  ] Or_error.t

val parse_handshake_frame : Cstruct.t -> (Cstruct.t option * Cstruct.t)
val parse_handshake : Cstruct.t -> Core.tls_handshake Or_error.t

val parse_alert     : Cstruct.t -> Core.tls_alert Or_error.t

val parse_change_cipher_spec   : Cstruct.t -> unit Or_error.t

val parse_certificate_request     : Cstruct.t -> (Packet.client_certificate_type list * Cstruct.t list) Or_error.t
val parse_certificate_request_1_2 : Cstruct.t -> (Packet.client_certificate_type list * (Nocrypto.Hash.hash * Packet.signature_algorithm_type) list * Cstruct.t list) Or_error.t

val parse_dh_parameters        : Cstruct.t -> (Core.dh_parameters * Cstruct.t * Cstruct.t) Or_error.t
val parse_digitally_signed     : Cstruct.t -> Cstruct.t Or_error.t
val parse_digitally_signed_1_2 : Cstruct.t -> (Nocrypto.Hash.hash * Packet.signature_algorithm_type * Cstruct.t) Or_error.t
