(** Ciphersuite definitions and some helper functions. *)

(** sum type of all possible key exchange methods *)
type key_exchange_algorithm_dhe = [ `FFDHE | `ECDHE ]
type key_exchange_algorithm = [ key_exchange_algorithm_dhe | `RSA ]

let pp_key_exchange_algorithm_dhe ppf = function
  | `FFDHE -> Fmt.string ppf "FFDHE"
  | `ECDHE -> Fmt.string ppf "ECDHE"

let pp_key_exchange_algorithm ppf = function
  | #key_exchange_algorithm_dhe as d -> pp_key_exchange_algorithm_dhe ppf d
  | `RSA -> Fmt.string ppf "RSA"

(** [required_usage kex] is [usage] which a certificate must have if it is used in the given [kex] method *)
let required_usage = function
  | #key_exchange_algorithm_dhe -> `Digital_signature
  | `RSA -> `Key_encipherment

type block_cipher =
  | TRIPLE_DES_EDE_CBC
  | AES_128_CBC
  | AES_256_CBC

let pp_block_cipher ppf = function
  | TRIPLE_DES_EDE_CBC -> Fmt.string ppf "3DES EDE CBC"
  | AES_128_CBC -> Fmt.string ppf "AES128 CBC"
  | AES_256_CBC -> Fmt.string ppf "AES256 CBC"

type aead_cipher =
  | AES_128_CCM
  | AES_256_CCM
  | AES_128_GCM
  | AES_256_GCM
  | CHACHA20_POLY1305

let pp_aead_cipher ppf = function
  | AES_128_CCM -> Fmt.string ppf "AES128 CCM"
  | AES_256_CCM -> Fmt.string ppf "AES256 CCM"
  | AES_128_GCM -> Fmt.string ppf "AES128 GCM"
  | AES_256_GCM -> Fmt.string ppf "AES256 GCM"
  | CHACHA20_POLY1305 -> Fmt.string ppf "CHACHA20 POLY1305"

type payload_protection13 = [ `AEAD of aead_cipher ]

let pp_payload_protection13 ppf = function
  | `AEAD a -> Fmt.pf ppf "AEAD %a" pp_aead_cipher a

type payload_protection =  [
  payload_protection13
  | `Block of block_cipher * Mirage_crypto.Hash.hash
  ]

let pp_hash ppf = function
  | `MD5 -> Fmt.string ppf "MD5"
  | `SHA1 -> Fmt.string ppf "SHA1"
  | `SHA224 -> Fmt.string ppf "SHA224"
  | `SHA256 -> Fmt.string ppf "SHA256"
  | `SHA384 -> Fmt.string ppf "SHA384"
  | `SHA512 -> Fmt.string ppf "SHA512"

let pp_payload_protection ppf = function
  | #payload_protection13 as p -> pp_payload_protection13 ppf p
  | `Block (b, h) -> Fmt.pf ppf "BLOCK %a %a" pp_block_cipher b pp_hash h

(* this is K_LEN, max 8 N_MIN from RFC5116 sections 5.1 & 5.2 -- as defined in TLS1.3 RFC 8446 Section 5.3 *)
let kn_13 = function
  | AES_128_GCM -> (16, 12)
  | AES_256_GCM -> (32, 12)
  | AES_128_CCM -> (16, 12)
  | AES_256_CCM -> (32, 12)
  | CHACHA20_POLY1305 -> (32, 12)

(** [key_length iv payload_protection] is [(key size, IV size, mac size)] where key IV, and mac sizes are the required bytes for the given [payload_protection] *)
(* NB only used for <= TLS 1.2, IV length for AEAD defined in RFC 5288 Section 3 (for GCM), salt[4] for CCM in RFC 6655 Section 3 *)
let key_length iv pp =
  let mac_size = Mirage_crypto.Hash.digest_size in
  match pp with
  | `AEAD AES_128_CCM                -> (16, 4 , 0)
  | `AEAD AES_256_CCM                -> (32, 4 , 0)
  | `AEAD AES_128_GCM                -> (16, 4 , 0)
  | `AEAD AES_256_GCM                -> (32, 4 , 0)
  | `AEAD CHACHA20_POLY1305          -> (32, 12, 0)
  | `Block (bc, mac) ->
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
  | `AES_128_GCM_SHA256
  | `AES_256_GCM_SHA384
  | `CHACHA20_POLY1305_SHA256
  | `AES_128_CCM_SHA256
]

let privprot13 = function
  | `AES_128_GCM_SHA256 -> AES_128_GCM
  | `AES_256_GCM_SHA384 -> AES_256_GCM
  | `CHACHA20_POLY1305_SHA256 -> CHACHA20_POLY1305
  | `AES_128_CCM_SHA256 -> AES_128_CCM

let hash13 = function
  | `AES_128_GCM_SHA256 -> `SHA256
  | `AES_256_GCM_SHA384 -> `SHA384
  | `CHACHA20_POLY1305_SHA256 -> `SHA256
  | `AES_128_CCM_SHA256 -> `SHA256

let any_ciphersuite_to_ciphersuite13 = function
  | Packet.TLS_AES_128_GCM_SHA256 -> Some `AES_128_GCM_SHA256
  | Packet.TLS_AES_256_GCM_SHA384 -> Some `AES_256_GCM_SHA384
  | Packet.TLS_CHACHA20_POLY1305_SHA256 -> Some `CHACHA20_POLY1305_SHA256
  | Packet.TLS_AES_128_CCM_SHA256 -> Some `AES_128_CCM_SHA256
  | _ -> None

type ciphersuite = [
  ciphersuite13
  | `DHE_RSA_WITH_AES_128_GCM_SHA256
  | `DHE_RSA_WITH_AES_256_GCM_SHA384
  | `DHE_RSA_WITH_AES_256_CCM
  | `DHE_RSA_WITH_AES_128_CCM
  | `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | `DHE_RSA_WITH_AES_256_CBC_SHA256
  | `DHE_RSA_WITH_AES_128_CBC_SHA256
  | `DHE_RSA_WITH_AES_256_CBC_SHA
  | `DHE_RSA_WITH_AES_128_CBC_SHA
  | `DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | `ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | `ECDHE_RSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | `ECDHE_RSA_WITH_AES_256_CBC_SHA384
  | `ECDHE_RSA_WITH_AES_128_CBC_SHA256
  | `ECDHE_RSA_WITH_AES_256_CBC_SHA
  | `ECDHE_RSA_WITH_AES_128_CBC_SHA
  | `ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
  | `RSA_WITH_AES_256_CBC_SHA256
  | `RSA_WITH_AES_128_CBC_SHA256
  | `RSA_WITH_AES_256_CBC_SHA
  | `RSA_WITH_AES_128_CBC_SHA
  | `RSA_WITH_3DES_EDE_CBC_SHA
  | `RSA_WITH_AES_128_GCM_SHA256
  | `RSA_WITH_AES_256_GCM_SHA384
  | `RSA_WITH_AES_256_CCM
  | `RSA_WITH_AES_128_CCM
  | `ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
  | `ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  | `ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  | `ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  | `ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  | `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  ]

let ciphersuite_to_ciphersuite13 : ciphersuite -> ciphersuite13 option = function
  | #ciphersuite13 as cs -> Some cs
  | _ -> None

let any_ciphersuite_to_ciphersuite = function
  | Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 -> Some `DHE_RSA_WITH_AES_256_CBC_SHA256
  | Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 -> Some `DHE_RSA_WITH_AES_128_CBC_SHA256
  | Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA    -> Some `DHE_RSA_WITH_AES_256_CBC_SHA
  | Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA    -> Some `DHE_RSA_WITH_AES_128_CBC_SHA
  | Packet.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   -> Some `DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | Packet.TLS_RSA_WITH_AES_256_CBC_SHA256     -> Some `RSA_WITH_AES_256_CBC_SHA256
  | Packet.TLS_RSA_WITH_AES_128_CBC_SHA256     -> Some `RSA_WITH_AES_128_CBC_SHA256
  | Packet.TLS_RSA_WITH_AES_256_CBC_SHA        -> Some `RSA_WITH_AES_256_CBC_SHA
  | Packet.TLS_RSA_WITH_AES_128_CBC_SHA        -> Some `RSA_WITH_AES_128_CBC_SHA
  | Packet.TLS_RSA_WITH_3DES_EDE_CBC_SHA       -> Some `RSA_WITH_3DES_EDE_CBC_SHA
  | Packet.TLS_RSA_WITH_AES_128_CCM            -> Some `RSA_WITH_AES_128_CCM
  | Packet.TLS_RSA_WITH_AES_256_CCM            -> Some `RSA_WITH_AES_256_CCM
  | Packet.TLS_DHE_RSA_WITH_AES_128_CCM        -> Some `DHE_RSA_WITH_AES_128_CCM
  | Packet.TLS_DHE_RSA_WITH_AES_256_CCM        -> Some `DHE_RSA_WITH_AES_256_CCM
  | Packet.TLS_RSA_WITH_AES_128_GCM_SHA256     -> Some `RSA_WITH_AES_128_GCM_SHA256
  | Packet.TLS_RSA_WITH_AES_256_GCM_SHA384     -> Some `RSA_WITH_AES_256_GCM_SHA384
  | Packet.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 -> Some `DHE_RSA_WITH_AES_128_GCM_SHA256
  | Packet.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -> Some `DHE_RSA_WITH_AES_256_GCM_SHA384
  | Packet.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> Some `ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | Packet.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> Some `ECDHE_RSA_WITH_AES_256_GCM_SHA384
  | Packet.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 -> Some `ECDHE_RSA_WITH_AES_256_CBC_SHA384
  | Packet.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -> Some `ECDHE_RSA_WITH_AES_128_CBC_SHA256
  | Packet.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA  -> Some `ECDHE_RSA_WITH_AES_256_CBC_SHA
  | Packet.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA  -> Some `ECDHE_RSA_WITH_AES_128_CBC_SHA
  | Packet.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA -> Some `ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
  | Packet.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -> Some `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | Packet.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -> Some `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | Packet.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA -> Some `ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
  | Packet.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA -> Some `ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  | Packet.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA -> Some `ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  | Packet.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -> Some `ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  | Packet.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 -> Some `ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  | Packet.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 -> Some `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | Packet.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 -> Some `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | Packet.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 -> Some `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  | x -> any_ciphersuite_to_ciphersuite13 x

let ciphersuite_to_any_ciphersuite = function
  | `DHE_RSA_WITH_AES_256_CBC_SHA256 -> Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  | `DHE_RSA_WITH_AES_128_CBC_SHA256 -> Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  | `DHE_RSA_WITH_AES_256_CBC_SHA    -> Packet.TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | `DHE_RSA_WITH_AES_128_CBC_SHA    -> Packet.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | `DHE_RSA_WITH_3DES_EDE_CBC_SHA   -> Packet.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  | `RSA_WITH_AES_256_CBC_SHA256     -> Packet.TLS_RSA_WITH_AES_256_CBC_SHA256
  | `RSA_WITH_AES_128_CBC_SHA256     -> Packet.TLS_RSA_WITH_AES_128_CBC_SHA256
  | `RSA_WITH_AES_256_CBC_SHA        -> Packet.TLS_RSA_WITH_AES_256_CBC_SHA
  | `RSA_WITH_AES_128_CBC_SHA        -> Packet.TLS_RSA_WITH_AES_128_CBC_SHA
  | `RSA_WITH_3DES_EDE_CBC_SHA       -> Packet.TLS_RSA_WITH_3DES_EDE_CBC_SHA
  | `RSA_WITH_AES_128_CCM            -> Packet.TLS_RSA_WITH_AES_128_CCM
  | `RSA_WITH_AES_256_CCM            -> Packet.TLS_RSA_WITH_AES_256_CCM
  | `DHE_RSA_WITH_AES_128_CCM        -> Packet.TLS_DHE_RSA_WITH_AES_128_CCM
  | `DHE_RSA_WITH_AES_256_CCM        -> Packet.TLS_DHE_RSA_WITH_AES_256_CCM
  | `RSA_WITH_AES_128_GCM_SHA256     -> Packet.TLS_RSA_WITH_AES_128_GCM_SHA256
  | `RSA_WITH_AES_256_GCM_SHA384     -> Packet.TLS_RSA_WITH_AES_256_GCM_SHA384
  | `DHE_RSA_WITH_AES_128_GCM_SHA256 -> Packet.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  | `DHE_RSA_WITH_AES_256_GCM_SHA384 -> Packet.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> Packet.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | `ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> Packet.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_RSA_WITH_AES_256_CBC_SHA384 -> Packet.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  | `ECDHE_RSA_WITH_AES_128_CBC_SHA256 -> Packet.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  | `ECDHE_RSA_WITH_AES_256_CBC_SHA  -> Packet.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  | `ECDHE_RSA_WITH_AES_128_CBC_SHA  -> Packet.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  | `ECDHE_RSA_WITH_3DES_EDE_CBC_SHA -> Packet.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
  | `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -> Packet.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -> Packet.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | `AES_128_GCM_SHA256 -> Packet.TLS_AES_128_GCM_SHA256
  | `AES_256_GCM_SHA384 -> Packet.TLS_AES_256_GCM_SHA384
  | `CHACHA20_POLY1305_SHA256 -> Packet.TLS_CHACHA20_POLY1305_SHA256
  | `AES_128_CCM_SHA256 -> Packet.TLS_AES_128_CCM_SHA256
  | `ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA -> Packet.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
  | `ECDHE_ECDSA_WITH_AES_128_CBC_SHA -> Packet.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  | `ECDHE_ECDSA_WITH_AES_256_CBC_SHA -> Packet.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  | `ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -> Packet.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  | `ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 -> Packet.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  | `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 -> Packet.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 -> Packet.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 -> Packet.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

(** [get_kex_privprot ciphersuite] is [(kex, privacy_protection)] where it dissects the [ciphersuite] into a pair containing the key exchange method [kex], and its [privacy_protection] *)
let get_keytype_kex_privprot = function
  | `RSA_WITH_3DES_EDE_CBC_SHA       -> (`RSA, `RSA, `Block (TRIPLE_DES_EDE_CBC, `SHA1))
  | `DHE_RSA_WITH_3DES_EDE_CBC_SHA   -> (`RSA, `FFDHE, `Block (TRIPLE_DES_EDE_CBC, `SHA1))
  | `RSA_WITH_AES_128_CBC_SHA        -> (`RSA, `RSA, `Block (AES_128_CBC, `SHA1))
  | `DHE_RSA_WITH_AES_128_CBC_SHA    -> (`RSA, `FFDHE, `Block (AES_128_CBC, `SHA1))
  | `RSA_WITH_AES_256_CBC_SHA        -> (`RSA, `RSA, `Block (AES_256_CBC, `SHA1))
  | `DHE_RSA_WITH_AES_256_CBC_SHA    -> (`RSA, `FFDHE, `Block (AES_256_CBC, `SHA1))
  | `RSA_WITH_AES_128_CBC_SHA256     -> (`RSA, `RSA, `Block (AES_128_CBC, `SHA256))
  | `RSA_WITH_AES_256_CBC_SHA256     -> (`RSA, `RSA, `Block (AES_256_CBC, `SHA256))
  | `DHE_RSA_WITH_AES_128_CBC_SHA256 -> (`RSA, `FFDHE, `Block (AES_128_CBC, `SHA256))
  | `DHE_RSA_WITH_AES_256_CBC_SHA256 -> (`RSA, `FFDHE, `Block (AES_256_CBC, `SHA256))
  | `RSA_WITH_AES_128_CCM            -> (`RSA, `RSA, `AEAD AES_128_CCM)
  | `RSA_WITH_AES_256_CCM            -> (`RSA, `RSA, `AEAD AES_256_CCM)
  | `DHE_RSA_WITH_AES_128_CCM        -> (`RSA, `FFDHE, `AEAD AES_128_CCM)
  | `DHE_RSA_WITH_AES_256_CCM        -> (`RSA, `FFDHE, `AEAD AES_256_CCM)
  | `RSA_WITH_AES_128_GCM_SHA256     -> (`RSA, `RSA, `AEAD AES_128_GCM)
  | `RSA_WITH_AES_256_GCM_SHA384     -> (`RSA, `RSA, `AEAD AES_256_GCM)
  | `DHE_RSA_WITH_AES_128_GCM_SHA256 -> (`RSA, `FFDHE, `AEAD AES_128_GCM)
  | `DHE_RSA_WITH_AES_256_GCM_SHA384 -> (`RSA, `FFDHE, `AEAD AES_256_GCM)
  | `ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> (`RSA, `ECDHE, `AEAD AES_128_GCM)
  | `ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> (`RSA, `ECDHE, `AEAD AES_256_GCM)
  | `ECDHE_RSA_WITH_AES_256_CBC_SHA384 -> (`RSA, `ECDHE, `Block (AES_256_CBC, `SHA384))
  | `ECDHE_RSA_WITH_AES_128_CBC_SHA256 -> (`RSA, `ECDHE, `Block (AES_128_CBC, `SHA256))
  | `ECDHE_RSA_WITH_AES_256_CBC_SHA -> (`RSA, `ECDHE, `Block (AES_256_CBC, `SHA1))
  | `ECDHE_RSA_WITH_AES_128_CBC_SHA -> (`RSA, `ECDHE, `Block (AES_128_CBC, `SHA1))
  | `ECDHE_RSA_WITH_3DES_EDE_CBC_SHA -> (`RSA, `ECDHE, `Block (TRIPLE_DES_EDE_CBC, `SHA1))
  | `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -> (`RSA, `FFDHE, `AEAD CHACHA20_POLY1305)
  | `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -> (`RSA, `ECDHE, `AEAD CHACHA20_POLY1305)
  | `ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA -> (`EC, `ECDHE, `Block (TRIPLE_DES_EDE_CBC, `SHA1))
  | `ECDHE_ECDSA_WITH_AES_128_CBC_SHA -> (`EC, `ECDHE, `Block (AES_128_CBC, `SHA1))
  | `ECDHE_ECDSA_WITH_AES_256_CBC_SHA -> (`EC, `ECDHE, `Block (AES_256_CBC, `SHA1))
  | `ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -> (`EC, `ECDHE, `Block (AES_128_CBC, `SHA256))
  | `ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 -> (`EC, `ECDHE, `Block (AES_256_CBC, `SHA384))
  | `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 -> (`EC, `ECDHE, `AEAD AES_128_GCM)
  | `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 -> (`EC, `ECDHE, `AEAD AES_256_GCM)
  | `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 -> (`EC, `ECDHE, `AEAD CHACHA20_POLY1305)
  | #ciphersuite13 as cs13 -> (`RSA, `FFDHE, `AEAD (privprot13 cs13)) (* this is mostly wrong *)

(** [ciphersuite_kex ciphersuite] is [kex], first projection of [get_kex_privprot] *)
let ciphersuite_kex c =
  let _keytype, kex, _pp = get_keytype_kex_privprot c in
  kex

(** [ciphersuite_privprot ciphersuite] is [privprot], second projection of [get_kex_privprot] *)
let ciphersuite_privprot c =
  let _keytype, _kex, pp = get_keytype_kex_privprot c in
  pp

let ciphersuite_keytype c =
  let keytype, _kex, _pp = get_keytype_kex_privprot c in
  keytype

let pp_ciphersuite ppf cs =
  let keytype, kex, pp = get_keytype_kex_privprot cs in
  let pp_keytype ppf = function
    | `EC -> Fmt.string ppf "ECDSA"
    | `RSA -> Fmt.string ppf "RSA"
  in
  match cs with
  | #ciphersuite13 -> Fmt.pf ppf "%a" pp_payload_protection pp
  | _ -> Fmt.pf ppf "%a %a %a" pp_key_exchange_algorithm kex pp_keytype keytype
           pp_payload_protection pp

let pp_any_ciphersuite ppf cs =
  match any_ciphersuite_to_ciphersuite cs with
  | Some cs -> pp_ciphersuite ppf cs
  | None -> Fmt.pf ppf "ciphersuite %04X" (Packet.any_ciphersuite_to_int cs)

let ciphersuite_fs cs =
  match ciphersuite_kex cs with
  | #key_exchange_algorithm_dhe -> true
  | `RSA -> false

let ecdhe_only = function
  | #ciphersuite13 -> false
  | cs -> match get_keytype_kex_privprot cs with
    | (_, `ECDHE, _) -> true
    | _ -> false

let dhe_only = function
  | #ciphersuite13 -> false
  | cs -> match get_keytype_kex_privprot cs with
    | (_, `FFDHE, _) -> true
    | _ -> false

let ecdhe = function
  | #ciphersuite13 -> true
  | cs -> match get_keytype_kex_privprot cs with
    | (_, `ECDHE, _) -> true
    | _ -> false

let ciphersuite_tls12_only = function
  | `DHE_RSA_WITH_AES_256_CBC_SHA256
  | `DHE_RSA_WITH_AES_128_CBC_SHA256
  | `RSA_WITH_AES_256_CBC_SHA256
  | `RSA_WITH_AES_128_CBC_SHA256
  | `RSA_WITH_AES_128_CCM
  | `RSA_WITH_AES_256_CCM
  | `DHE_RSA_WITH_AES_128_CCM
  | `DHE_RSA_WITH_AES_256_CCM
  | `RSA_WITH_AES_128_GCM_SHA256
  | `RSA_WITH_AES_256_GCM_SHA384
  | `DHE_RSA_WITH_AES_128_GCM_SHA256
  | `DHE_RSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | `ECDHE_RSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_RSA_WITH_AES_256_CBC_SHA384
  | `ECDHE_RSA_WITH_AES_128_CBC_SHA256
  | `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  | `ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  | `ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  | `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 -> true
  | _ -> false

let ciphersuite_tls13 = function
  | #ciphersuite13 -> true
  | _ -> false
