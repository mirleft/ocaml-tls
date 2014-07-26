open State

val initialise_crypto_ctx : epoch_data -> handshake_params -> Cstruct.t -> (crypto_context * crypto_context * Cstruct.t)
val finished : Core.tls_version -> Cstruct.t -> string -> Cstruct.t list -> Cstruct.t
