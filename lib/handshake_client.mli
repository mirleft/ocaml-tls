open Core
open State

val default_client_hello : Config.config -> (tls_version client_hello * handshake_params)
val handle_change_cipher_spec : client_handshake_state -> handshake_state -> Cstruct.t -> ccs_return or_error
val handle_handshake : client_handshake_state -> handshake_state -> Cstruct.t -> handshake_return or_error
val answer_hello_request : handshake_state -> handshake_return or_error
