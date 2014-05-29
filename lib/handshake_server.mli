open Core
open State

val handle_change_cipher_spec : server_handshake_state -> handshake_state -> Cstruct.t -> ccs_return or_error
val handle_handshake : server_handshake_state -> handshake_state -> Cstruct.t -> handshake_return or_error
