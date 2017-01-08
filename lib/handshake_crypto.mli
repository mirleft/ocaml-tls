open State

val derive_master_secret : Types.tls_version -> session_data -> Cstruct.t -> Cstruct.t list -> Types.master_secret
val initialise_crypto_ctx : Types.tls_version -> session_data -> (crypto_context * crypto_context)
val finished : Types.tls_version -> Ciphersuite.ciphersuite -> Cstruct.t -> string -> Cstruct.t list -> Cstruct.t
