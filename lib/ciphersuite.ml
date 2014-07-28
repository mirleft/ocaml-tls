(** Ciphersuite helper functions and definitions. Including mapping to reserved numbers and dissecting into key exchange, encryption, and hash algorithm. *)

(** sum type of all possible key exchange methods *)
type key_exchange_algorithm =
  | RSA
  | DHE_RSA
  with sexp

(** [needs_certificate kex] is a predicate which is true if the [kex] requires a server certificate *)
let needs_certificate = function
  | RSA | DHE_RSA -> true

(** [needs_server_kex kex] is a predicate which is true if the [kex] requires a server key exchange messag *)
let needs_server_kex = function
  | DHE_RSA -> true
  | RSA     -> false

(** [required_keytype_and_usage kex] is [(keytype, usage)] which a certificate must have if it is used in the given [kex] method *)
let required_keytype_and_usage = function
  | RSA      -> (`RSA, `Key_encipherment)
  | DHE_RSA  -> (`RSA, `Digital_signature) (* signing with the signature scheme and hash algorithm that will be employed in the server key exchange message. *)

(** sum type of all possible encryption algorithms *)
type encryption_algorithm =
  | RC4_128
  | TRIPLE_DES_EDE_CBC
  | AES_128_CBC
  | AES_256_CBC
  with sexp

(** [key_length encryption_algorithm] is [(key size, IV size)] where key and IV size are the required bytes for the given [encryption_algorithm] *)
let key_lengths = function
  | RC4_128 -> (16, 0)
  | TRIPLE_DES_EDE_CBC -> (24, 8)
  | AES_128_CBC -> (16, 16)
  | AES_256_CBC -> (32, 16)

type ciphersuite = [
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | `TLS_RSA_WITH_AES_256_CBC_SHA256
  | `TLS_RSA_WITH_AES_128_CBC_SHA256
  | `TLS_RSA_WITH_AES_256_CBC_SHA
  | `TLS_RSA_WITH_AES_128_CBC_SHA
  | `TLS_RSA_WITH_3DES_EDE_CBC_SHA
  | `TLS_RSA_WITH_RC4_128_SHA
  | `TLS_RSA_WITH_RC4_128_MD5
]  with sexp

let any_ciphersuite_to_ciphersuite = function
  | Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 -> Some `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 -> Some `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA    -> Some `TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA    -> Some `TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | Packet.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   -> Some `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | Packet.TLS_RSA_WITH_AES_256_CBC_SHA256     -> Some `TLS_RSA_WITH_AES_256_CBC_SHA256
  | Packet.TLS_RSA_WITH_AES_128_CBC_SHA256     -> Some `TLS_RSA_WITH_AES_128_CBC_SHA256
  | Packet.TLS_RSA_WITH_AES_256_CBC_SHA        -> Some `TLS_RSA_WITH_AES_256_CBC_SHA
  | Packet.TLS_RSA_WITH_AES_128_CBC_SHA        -> Some `TLS_RSA_WITH_AES_128_CBC_SHA
  | Packet.TLS_RSA_WITH_3DES_EDE_CBC_SHA       -> Some `TLS_RSA_WITH_3DES_EDE_CBC_SHA
  | Packet.TLS_RSA_WITH_RC4_128_SHA            -> Some `TLS_RSA_WITH_RC4_128_SHA
  | Packet.TLS_RSA_WITH_RC4_128_MD5            -> Some `TLS_RSA_WITH_RC4_128_MD5
  | _                                          -> None

let ciphersuite_to_any_ciphersuite = function
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 -> Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 -> Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA    -> Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA    -> Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   -> Packet.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | `TLS_RSA_WITH_AES_256_CBC_SHA256     -> Packet.TLS_RSA_WITH_AES_256_CBC_SHA256
  | `TLS_RSA_WITH_AES_128_CBC_SHA256     -> Packet.TLS_RSA_WITH_AES_128_CBC_SHA256
  | `TLS_RSA_WITH_AES_256_CBC_SHA        -> Packet.TLS_RSA_WITH_AES_256_CBC_SHA
  | `TLS_RSA_WITH_AES_128_CBC_SHA        -> Packet.TLS_RSA_WITH_AES_128_CBC_SHA
  | `TLS_RSA_WITH_3DES_EDE_CBC_SHA       -> Packet.TLS_RSA_WITH_3DES_EDE_CBC_SHA
  | `TLS_RSA_WITH_RC4_128_SHA            -> Packet.TLS_RSA_WITH_RC4_128_SHA
  | `TLS_RSA_WITH_RC4_128_MD5            -> Packet.TLS_RSA_WITH_RC4_128_MD5

let ciphersuite_to_string x= Packet.any_ciphersuite_to_string (ciphersuite_to_any_ciphersuite x)

(** [get_kex_enc_hash ciphersuite] is [(kex, enc, hash)] where it dissects the [ciphersuite] into a tuple containing the key exchange method [kex], encryption algorithm [enc], and hash algorithm [hash] *)
let get_kex_enc_hash = function
  | `TLS_RSA_WITH_RC4_128_MD5            -> (RSA, RC4_128, Packet.MD5)
  | `TLS_RSA_WITH_RC4_128_SHA            -> (RSA, RC4_128, Packet.SHA)
  | `TLS_RSA_WITH_3DES_EDE_CBC_SHA       -> (RSA, TRIPLE_DES_EDE_CBC, Packet.SHA)
  | `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   -> (DHE_RSA, TRIPLE_DES_EDE_CBC, Packet.SHA)
  | `TLS_RSA_WITH_AES_128_CBC_SHA        -> (RSA, AES_128_CBC, Packet.SHA)
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA    -> (DHE_RSA, AES_128_CBC, Packet.SHA)
  | `TLS_RSA_WITH_AES_256_CBC_SHA        -> (RSA, AES_256_CBC, Packet.SHA)
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA    -> (DHE_RSA, AES_256_CBC, Packet.SHA)
  | `TLS_RSA_WITH_AES_128_CBC_SHA256     -> (RSA, AES_128_CBC, Packet.SHA256)
  | `TLS_RSA_WITH_AES_256_CBC_SHA256     -> (RSA, AES_256_CBC, Packet.SHA256)
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 -> (DHE_RSA, AES_128_CBC, Packet.SHA256)
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 -> (DHE_RSA, AES_256_CBC, Packet.SHA256)

(** [ciphersuite_kex ciphersuite] is [kex], first projection of [get_kex_enc_hash] *)
let ciphersuite_kex c = let (k, _, _) = get_kex_enc_hash c in k

(** [ciphersuite_cipher ciphersuite] is [enc], second projection of [get_kex_enc_hash] *)
let ciphersuite_cipher c = let (_, k, _) = get_kex_enc_hash c in k

(** [ciphersuite_mac ciphersuite] is [hash], third projection of [get_kex_enc_hash] *)
let ciphersuite_mac c = let (_, _, k) = get_kex_enc_hash c in k

(** [ciphersuite_cipher_mac_length ciphersuite] is [(key size, IV size)] of the given [ciphersuite], using [key_lengths] *)
let ciphersuite_cipher_mac_length c =
  let cipher = ciphersuite_cipher c in
  key_lengths cipher

let ciphersuite_pfs cs =
  match ciphersuite_kex cs with
  | DHE_RSA -> true
  | RSA     -> false

let ciphersuite_tls12_only = function
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 -> true
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 -> true
  | `TLS_RSA_WITH_AES_256_CBC_SHA256     -> true
  | `TLS_RSA_WITH_AES_128_CBC_SHA256     -> true
  | _                                    -> false
