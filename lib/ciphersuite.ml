(** Ciphersuite definitions and some helper functions. *)

(** sum type of all possible key exchange methods *)
type key_exchange_algorithm =
  | RSA
  | DHE_RSA
  [@@deriving sexp]

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

type stream_cipher =
  | RC4_128
  [@@deriving sexp]

type block_cipher =
  | TRIPLE_DES_EDE_CBC
  | AES_128_CBC
  | AES_256_CBC
  [@@deriving sexp]

type aead_cipher =
  | AES_128_CCM
  | AES_256_CCM
  | AES_128_GCM
  | AES_256_GCM
  [@@deriving sexp]

(* this is K_LEN, max 8 N_MIN from RFC5116 -- as defined in TLS1.3 spec *)
let kn = function
  | AES_128_GCM -> (16, 12)
  | AES_256_GCM -> (32, 12)
  | AES_128_CCM -> (16, 12)
  | AES_256_CCM -> (32, 12)

type payload_protection =
  | Stream of stream_cipher * Nocrypto.Hash.hash
  | Block of block_cipher * Nocrypto.Hash.hash
  | AEAD of aead_cipher
  [@@deriving sexp]

(** [key_length iv payload_protection] is [(key size, IV size, mac size)] where key IV, and mac sizes are the required bytes for the given [payload_protection] *)
let key_length iv pp =
  let mac_size = Nocrypto.Hash.digest_size in
  match pp with
  | Stream (RC4_128, mac)           -> (16, 0 , mac_size mac)
  | AEAD AES_128_CCM                -> (16, 4 , 0)
  | AEAD AES_256_CCM                -> (32, 4 , 0)
  | AEAD AES_128_GCM                -> (16, 4 , 0)
  | AEAD AES_256_GCM                -> (32, 4 , 0)
  | Block (bc, mac) ->
     let keylen, ivlen = match bc with
       | TRIPLE_DES_EDE_CBC -> (24, 8)
       | AES_128_CBC        -> (16, 16)
       | AES_256_CBC        -> (32, 16)
     and maclen = mac_size mac
     in
     match iv with
     | None -> (keylen, 0, maclen)
     | Some () -> (keylen, ivlen, maclen)

type ciphersuite13 = [
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
  | `TLS_DHE_RSA_WITH_AES_256_CCM
  | `TLS_DHE_RSA_WITH_AES_128_CCM
] [@@deriving sexp]

let hash_of = function
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 -> `SHA256
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> `SHA384
  | `TLS_DHE_RSA_WITH_AES_256_CCM -> `SHA256
  | `TLS_DHE_RSA_WITH_AES_128_CCM -> `SHA256
  | _ -> assert false

type ciphersuite = [
  ciphersuite13
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
  | `TLS_RSA_WITH_AES_128_GCM_SHA256
  | `TLS_RSA_WITH_AES_256_GCM_SHA384
  | `TLS_RSA_WITH_AES_256_CCM
  | `TLS_RSA_WITH_AES_128_CCM
]  [@@deriving sexp]

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
  | Packet.TLS_RSA_WITH_AES_128_CCM            -> Some `TLS_RSA_WITH_AES_128_CCM
  | Packet.TLS_RSA_WITH_AES_256_CCM            -> Some `TLS_RSA_WITH_AES_256_CCM
  | Packet.TLS_DHE_RSA_WITH_AES_128_CCM        -> Some `TLS_DHE_RSA_WITH_AES_128_CCM
  | Packet.TLS_DHE_RSA_WITH_AES_256_CCM        -> Some `TLS_DHE_RSA_WITH_AES_256_CCM
  | Packet.TLS_RSA_WITH_AES_128_GCM_SHA256     -> Some `TLS_RSA_WITH_AES_128_GCM_SHA256
  | Packet.TLS_RSA_WITH_AES_256_GCM_SHA384     -> Some `TLS_RSA_WITH_AES_256_GCM_SHA384
  | Packet.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 -> Some `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | Packet.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> Some `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
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
  | `TLS_RSA_WITH_AES_128_CCM            -> Packet.TLS_RSA_WITH_AES_128_CCM
  | `TLS_RSA_WITH_AES_256_CCM            -> Packet.TLS_RSA_WITH_AES_256_CCM
  | `TLS_DHE_RSA_WITH_AES_128_CCM        -> Packet.TLS_DHE_RSA_WITH_AES_128_CCM
  | `TLS_DHE_RSA_WITH_AES_256_CCM        -> Packet.TLS_DHE_RSA_WITH_AES_256_CCM
  | `TLS_RSA_WITH_AES_128_GCM_SHA256     -> Packet.TLS_RSA_WITH_AES_128_GCM_SHA256
  | `TLS_RSA_WITH_AES_256_GCM_SHA384     -> Packet.TLS_RSA_WITH_AES_256_GCM_SHA384
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 -> Packet.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> Packet.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384

let ciphersuite_to_string x= Packet.any_ciphersuite_to_string (ciphersuite_to_any_ciphersuite x)

let privprot13 = function
  | `TLS_DHE_RSA_WITH_AES_128_CCM        -> AES_128_CCM
  | `TLS_DHE_RSA_WITH_AES_256_CCM        -> AES_256_CCM
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 -> AES_128_GCM
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> AES_256_GCM
  | _ -> assert false

(** [get_kex_privprot ciphersuite] is [(kex, privacy_protection)] where it dissects the [ciphersuite] into a pair containing the key exchange method [kex], and its [privacy_protection] *)
let get_kex_privprot = function
  | `TLS_RSA_WITH_RC4_128_MD5            -> (RSA    , Stream (RC4_128, `MD5))
  | `TLS_RSA_WITH_RC4_128_SHA            -> (RSA    , Stream (RC4_128, `SHA1))
  | `TLS_RSA_WITH_3DES_EDE_CBC_SHA       -> (RSA    , Block (TRIPLE_DES_EDE_CBC, `SHA1))
  | `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   -> (DHE_RSA, Block (TRIPLE_DES_EDE_CBC, `SHA1))
  | `TLS_RSA_WITH_AES_128_CBC_SHA        -> (RSA    , Block (AES_128_CBC, `SHA1))
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA    -> (DHE_RSA, Block (AES_128_CBC, `SHA1))
  | `TLS_RSA_WITH_AES_256_CBC_SHA        -> (RSA    , Block (AES_256_CBC, `SHA1))
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA    -> (DHE_RSA, Block (AES_256_CBC, `SHA1))
  | `TLS_RSA_WITH_AES_128_CBC_SHA256     -> (RSA    , Block (AES_128_CBC, `SHA256))
  | `TLS_RSA_WITH_AES_256_CBC_SHA256     -> (RSA    , Block (AES_256_CBC, `SHA256))
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 -> (DHE_RSA, Block (AES_128_CBC, `SHA256))
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 -> (DHE_RSA, Block (AES_256_CBC, `SHA256))
  | `TLS_RSA_WITH_AES_128_CCM            -> (RSA    , AEAD AES_128_CCM)
  | `TLS_RSA_WITH_AES_256_CCM            -> (RSA    , AEAD AES_256_CCM)
  | `TLS_DHE_RSA_WITH_AES_128_CCM        -> (DHE_RSA, AEAD AES_128_CCM)
  | `TLS_DHE_RSA_WITH_AES_256_CCM        -> (DHE_RSA, AEAD AES_256_CCM)
  | `TLS_RSA_WITH_AES_128_GCM_SHA256     -> (RSA    , AEAD AES_128_GCM)
  | `TLS_RSA_WITH_AES_256_GCM_SHA384     -> (RSA    , AEAD AES_256_GCM)
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 -> (DHE_RSA, AEAD AES_128_GCM)
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> (DHE_RSA, AEAD AES_256_GCM)

(** [ciphersuite_kex ciphersuite] is [kex], first projection of [get_kex_privprot] *)
let ciphersuite_kex c = fst (get_kex_privprot c)

(** [ciphersuite_privprot ciphersuite] is [privprot], second projection of [get_kex_privprot] *)
let ciphersuite_privprot c = snd (get_kex_privprot c)

let ciphersuite_fs cs =
  match ciphersuite_kex cs with
  | DHE_RSA -> true
  | RSA     -> false

let ciphersuite_tls12_only = function
  | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | `TLS_RSA_WITH_AES_256_CBC_SHA256
  | `TLS_RSA_WITH_AES_128_CBC_SHA256
  | `TLS_RSA_WITH_AES_128_CCM
  | `TLS_RSA_WITH_AES_256_CCM
  | `TLS_DHE_RSA_WITH_AES_128_CCM
  | `TLS_DHE_RSA_WITH_AES_256_CCM
  | `TLS_RSA_WITH_AES_128_GCM_SHA256
  | `TLS_RSA_WITH_AES_256_GCM_SHA384
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> true
  | _                                    -> false

let ciphersuite_tls13 = function
  | `TLS_DHE_RSA_WITH_AES_128_CCM
  | `TLS_DHE_RSA_WITH_AES_256_CCM
  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> true
  | _                                    -> false

let any_group_to_group =
  let open Nocrypto.Dh.Group in
  function
  | Packet.FFDHE2048 -> Some ffdhe2048
  | Packet.FFDHE3072 -> Some ffdhe3072
  | Packet.FFDHE4096 -> Some ffdhe4096
  | Packet.FFDHE6144 -> Some ffdhe6144
  | Packet.FFDHE8192 -> Some ffdhe8192
  | _ -> None

let group_to_any_group =
  let open Nocrypto.Dh.Group in
  function
   | x when x = ffdhe2048 -> Packet.FFDHE2048
   | x when x = ffdhe3072 -> Packet.FFDHE3072
   | x when x = ffdhe4096 -> Packet.FFDHE4096
   | x when x = ffdhe6144 -> Packet.FFDHE6144
   | x when x = ffdhe8192 -> Packet.FFDHE8192
   | _ -> assert false
