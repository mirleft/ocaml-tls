open Core
open State

val default_client_hello : Config.config -> (client_hello * tls_version)
val handle_change_cipher_spec : client_handshake_state -> handshake_state -> Cstruct.t -> handshake_return or_error
val handle_handshake : client_handshake_state -> handshake_state -> Cstruct.t -> handshake_return or_error
val answer_hello_request : handshake_state -> handshake_return or_error
