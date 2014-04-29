
type error =
  | Overflow
  | Unknown of string

module Or_error :
  sig
    type 'a or_error = Ok of 'a | Error of error
    val fail : error -> 'a or_error
    val is_success : 'a or_error -> bool
    val is_error : 'a or_error -> bool
    val return : 'a -> 'a or_error
    val ( >>= ) : 'a or_error -> ('a -> 'b or_error) -> 'b or_error
    val ( >|= ) : ('a -> 'b) -> 'a or_error -> 'b or_error
    val map : ('a -> 'b) -> 'a or_error -> 'b or_error
    val sequence : 'a or_error list -> 'a list or_error
    val sequence_ : 'a or_error list -> unit or_error
    val mapM : ('a -> 'b or_error) -> 'a list -> 'b list or_error
    val mapM_ : ('a -> 'b or_error) -> 'a list -> unit or_error
    val foldM : ('a -> 'b -> 'a or_error) -> 'a -> 'b list -> 'a or_error
  end

val parse_version   : Cstruct.t -> Core.tls_version Or_error.or_error
val parse_hdr       : Cstruct.t -> Packet.content_type option * Core.tls_version option * int

val parse_handshake : Cstruct.t -> Core.tls_handshake Or_error.or_error

val parse_alert     : Cstruct.t -> Core.tls_alert Or_error.or_error

val parse_dh_parameters : Cstruct.t -> (Core.dh_parameters * Cstruct.t * Cstruct.t) Or_error.or_error
val parse_digitally_signed : Cstruct.t -> Cstruct.t Or_error.or_error
val parse_digitally_signed_1_2 : Cstruct.t -> (Ciphersuite.hash_algorithm * Packet.signature_algorithm_type * Cstruct.t) Or_error.or_error
