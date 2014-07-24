
val assemble_protocol_version : Core.tls_version -> Cstruct.t

val assemble_handshake : Core.tls_handshake -> Cstruct.t

val assemble_hdr : Core.tls_version -> (Packet.content_type * Cstruct.t) -> Cstruct.t

val assemble_alert : ?level:Packet.alert_level -> Packet.alert_type -> Cstruct.t

val assemble_change_cipher_spec : Cstruct.t

val assemble_dh_parameters : Core.dh_parameters -> Cstruct.t

val assemble_digitally_signed : Cstruct.t -> Cstruct.t

val assemble_digitally_signed_1_2 : Packet.hash_algorithm -> Packet.signature_algorithm_type -> Cstruct.t -> Cstruct.t
