open Tls_state

val derive_master_secret : Tls_core.tls_version -> session_data -> Cstruct.t -> Cstruct.t list -> Tls_core.master_secret
val initialise_crypto_ctx : Tls_core.tls_version -> session_data -> (crypto_context * crypto_context)
val finished : Tls_core.tls_version -> Tls_ciphersuite.ciphersuite -> Cstruct.t -> string -> Cstruct.t list -> Cstruct.t
