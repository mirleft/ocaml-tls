
type error =
  | TrailingBytes  of string
  | WrongLength    of string
  | Unknown        of string

val pp_error : error Fmt.t

val parse_version     : string -> (Core.tls_version, error) result
val parse_any_version : string -> (Core.tls_any_version, error) result
val parse_record      : string ->
  ([ `Record of (Core.tls_hdr * string) * string
   | `Fragment of string
   ], [> `UnknownContentType of int
      | `UnknownRecordVersion of int * int
      | `RecordOverflow of int ]) result

val parse_handshake_frame : string -> (string option * string)
val parse_handshake : string -> (Core.tls_handshake, error) result

val parse_alert     : string -> (Core.tls_alert, error) result

val parse_change_cipher_spec   : string -> (unit, error) result

val parse_certificate_request     : string -> (Packet.client_certificate_type list * string list, error) result
val parse_certificate_request_1_2 : string -> (Packet.client_certificate_type list * Core.signature_algorithm list * string list, error) result
val parse_certificate_request_1_3 : string -> (string option * Core.certificate_request_extension list, error) result

val parse_certificates : string -> (string list, error) result
val parse_certificates_1_3 : string -> (string * (string * 'a list) list, error) result

val parse_client_dh_key_exchange : string -> (string, error) result
val parse_client_ec_key_exchange : string -> (string, error) result

val parse_dh_parameters        : string -> (Core.dh_parameters * string * string, error) result
val parse_ec_parameters        : string -> ([ `X25519 | `P256 | `P384 | `P521 ] * string * string * string, error) result
val parse_digitally_signed     : string -> (string, error) result
val parse_digitally_signed_1_2 : string -> (Core.signature_algorithm * string, error) result
