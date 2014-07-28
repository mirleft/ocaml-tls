open State

val initialise_crypto_ctx : Core.tls_version -> session_data -> Cstruct.t -> (crypto_context * crypto_context * Cstruct.t)
val finished : Core.tls_version -> Cstruct.t -> string -> Cstruct.t list -> Cstruct.t
