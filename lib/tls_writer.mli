
val assemble_protocol_version : Tls_core.tls_version -> Cstruct.t

val assemble_handshake : Tls_core.tls_handshake -> Cstruct.t

val assemble_hdr : Tls_core.tls_version -> (Tls_packet.content_type * Cstruct.t) -> Cstruct.t

val assemble_alert : ?level:Tls_packet.alert_level -> Tls_packet.alert_type -> Cstruct.t

val assemble_change_cipher_spec : Cstruct.t

val assemble_dh_parameters : Tls_core.dh_parameters -> Cstruct.t

val assemble_digitally_signed : Cstruct.t -> Cstruct.t

val assemble_digitally_signed_1_2 : Nocrypto.Hash.hash -> Tls_packet.signature_algorithm_type -> Cstruct.t -> Cstruct.t

val assemble_certificate_request : Tls_packet.client_certificate_type list -> Cstruct.t list -> Cstruct.t

val assemble_certificate_request_1_2 : Tls_packet.client_certificate_type list -> (Nocrypto.Hash.hash * Tls_packet.signature_algorithm_type) list -> Cstruct.t list -> Cstruct.t
