open Mirage_crypto

open Ciphersuite

(* on-the-wire dh_params <-> (group, pub_message) *)
let dh_params_pack { Mirage_crypto_pk.Dh.p; gg ; _ } message =
  let cs_of_z = Mirage_crypto_pk.Z_extra.to_octets_be ?size:None in
  { Core.dh_p = cs_of_z p ; dh_g = cs_of_z gg ; dh_Ys = message }

and dh_params_unpack { Core.dh_p ; dh_g ; dh_Ys } =
  let z_of_cs = Mirage_crypto_pk.Z_extra.of_octets_be ?bits:None in
  match Mirage_crypto_pk.Dh.group ~p:(z_of_cs dh_p) ~gg:(z_of_cs dh_g) () with
  | Ok dh -> Ok (dh, dh_Ys)
  | Error _ as e -> e

module Ciphers = struct

  (* I'm not sure how to get rid of this type, but would welcome a solution *)
  (* only used as result of get_block, which is called by get_cipher below *)
  type keyed = | K_CBC : 'k State.cbc_cipher * (string -> 'k) -> keyed

  let get_block = function
    | TRIPLE_DES_EDE_CBC ->
        K_CBC ( (module DES.CBC : Block.CBC with type key = DES.CBC.key),
                DES.CBC.of_secret )

    | AES_128_CBC ->
        K_CBC ( (module AES.CBC : Block.CBC with type key = AES.CBC.key),
                AES.CBC.of_secret )

    | AES_256_CBC ->
        K_CBC ( (module AES.CBC : Block.CBC with type key = AES.CBC.key),
                AES.CBC.of_secret )

  type aead_keyed = | K_AEAD : 'k State.aead_cipher * (string -> 'k) * bool -> aead_keyed
  let get_aead =
    function
    | AES_128_CCM | AES_256_CCM ->
       K_AEAD ((module AES.CCM16 : AEAD with type key = AES.CCM16.key),
               AES.CCM16.of_secret, true)
    | AES_128_GCM | AES_256_GCM ->
       K_AEAD ((module AES.GCM : AEAD with type key = AES.GCM.key),
               AES.GCM.of_secret, true)
    | CHACHA20_POLY1305 ->
       K_AEAD ((module Chacha20 : AEAD with type key = Chacha20.key),
               Chacha20.of_secret, false)

  let get_aead_cipher ~secret ~nonce aead_cipher =
    match get_aead aead_cipher with
    | K_AEAD (cipher, sec, explicit_nonce) ->
      let cipher_secret = sec secret in
      State.(AEAD { cipher ; cipher_secret ; nonce ; explicit_nonce })

  let get_cipher ~secret ~hmac_secret ~iv_mode ~nonce = function
    | `Block (cipher, hmac) ->
       ( match get_block cipher with
         | K_CBC (cipher, sec) ->
            let cipher_secret = sec secret in
            State.(CBC { cipher ; cipher_secret ; iv_mode ; hmac ; hmac_secret })
       )

    | `AEAD cipher -> get_aead_cipher ~secret ~nonce cipher
end

let sequence_buf seq =
  let buf = Bytes.create 8 in
  Bytes.set_int64_be buf 0 seq ;
  Bytes.unsafe_to_string buf

let aead_nonce nonce seq =
  let s =
    let l = String.length nonce in
    let buf = Bytes.make l '\x00' in
    Bytes.set_int64_be buf (l - 8) seq;
    Bytes.unsafe_to_string buf
  in
  Uncommon.xor nonce s

let adata_1_3 len =
  (* additional data in TLS 1.3 is using the header (RFC 8446 Section 5.2):
     - APPLICATION_TYPE
     - 0x03 0x03 (for TLS version 1.2 -- binary representation is 0x03 0x03)
     - <length in 16 bit>
  *)
  let buf = Bytes.create 5 in
  Bytes.set_uint8 buf 0 (Packet.content_type_to_int Packet.APPLICATION_DATA) ;
  Bytes.set_uint8 buf 1 3;
  Bytes.set_uint8 buf 2 3;
  Bytes.set_uint16_be buf 3 len ;
  Bytes.unsafe_to_string buf

let pseudo_header seq ty (v_major, v_minor) v_length =
  let buf = Bytes.create 13 in
  Bytes.set_int64_be buf 0 seq;
  Bytes.set_uint8 buf 8 (Packet.content_type_to_int ty);
  Bytes.set_uint8 buf 9 v_major;
  Bytes.set_uint8 buf 10 v_minor;
  Bytes.set_uint16_be buf 11 v_length;
  Bytes.unsafe_to_string buf

(* MAC used in TLS *)
let mac hash key pseudo_hdr data =
  let module H = (val Digestif.module_of_hash' hash) in
  H.(to_raw_string (hmac_string ~key (pseudo_hdr ^ data)))

let cbc_block (type a) cipher =
  let module C = (val cipher : Block.CBC with type key = a) in C.block_size

(* crazy CBC padding and unpadding for TLS *)
let cbc_pad block data =
  (* 1 is the padding length, encoded as 8 bit at the end of the fragment *)
  let len = 1 + String.length data in
  (* we might want to add additional blocks of padding *)
  let padding_length = block - (len mod block) in
  (* 1 is again padding length field *)
  let cstruct_len = padding_length + 1 in
  String.make cstruct_len (Char.unsafe_chr padding_length)

let cbc_unpad data =
  let len = String.length data in
  let padlen = String.get_uint8 data (pred len) in

  let rec check = function
    | i when i > padlen -> true
    | i -> (String.get_uint8 data (len - padlen - 1 + i) = padlen) && check (succ i) in

  try
    if check 0 then Some (String.sub data 0 (len - padlen - 1)) else None
  with Invalid_argument _ -> None

let tag_len (type a) cipher =
  let module C = (val cipher : AEAD with type key = a) in
  C.tag_size

let encrypt_aead (type a) ~cipher ~key ~nonce ?adata data =
  let module C = (val cipher : AEAD with type key = a) in
  C.authenticate_encrypt ~key ~nonce ?adata data

let decrypt_aead (type a) ~cipher ~key ~nonce ?adata data =
  let module C = (val cipher : AEAD with type key = a) in
  C.authenticate_decrypt ~key ~nonce ?adata data

let encrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : Block.CBC with type key = a) in
  let message = C.encrypt ~key ~iv (data ^ cbc_pad C.block_size data) in
  (message, C.next_iv ~iv message)

let decrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : Block.CBC with type key = a) in
  try
    let message = C.decrypt ~key ~iv data in
    match cbc_unpad message with
    | Some res -> Some (res, C.next_iv ~iv data)
    | None     -> None
  with
  (* This bails out immediately on mis-alignment, making it very timeable.
   * However, decryption belongs to the outermost level and this operation's
   * timing does not leak information ala padding oracle and friends. *)
  | Invalid_argument _ -> None
