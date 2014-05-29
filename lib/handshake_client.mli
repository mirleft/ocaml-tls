open Core
open State

val default_client_hello : Config.config -> (Core.client_hello * handshake_params)
val handle_change_cipher_spec : client_handshake_state -> handshake_state -> Cstruct.t -> handshake_return or_error
val handle_handshake : client_handshake_state -> handshake_state -> tls_handshake -> Cstruct.t -> handshake_return or_error
