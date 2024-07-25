
val assemble_protocol_version : ?buf:bytes -> Core.tls_version -> string

val assemble_handshake : Core.tls_handshake -> string

val assemble_message_hash : int -> string

val assemble_hdr : Core.tls_version -> (Packet.content_type * string) -> string

val assemble_alert : ?level:Packet.alert_level -> Packet.alert_type -> string

val assemble_change_cipher_spec : string

val assemble_dh_parameters : Core.dh_parameters -> string

val assemble_ec_parameters : Core.group -> string -> string

val assemble_client_dh_key_exchange : string -> string

val assemble_client_ec_key_exchange : string -> string

val assemble_digitally_signed : string -> string

val assemble_digitally_signed_1_2 : Core.signature_algorithm -> string -> string

val assemble_certificate_request : Packet.client_certificate_type list -> string list -> string

val assemble_certificate_request_1_2 : Packet.client_certificate_type list -> Core.signature_algorithm list -> string list -> string

val assemble_certificate_request_1_3 : ?context:string -> Core.certificate_request_extension list -> string

val assemble_certificates : string list -> string

val assemble_certificates_1_3 : string -> string list -> string
