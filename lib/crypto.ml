
open Nocrypto
open Nocrypto.Uncommon

open Ciphersuite
open Packet

let (<+>) = Utils.Cs.(<+>)


(* on-the-wire dh_params <-> (group, pub_message) *)
let dh_params_pack { Dh.p; gg } message =
  let cs_of_z = Numeric.Z.to_cstruct_be ?size:None in
  { Core.dh_p = cs_of_z p ; dh_g = cs_of_z gg ; dh_Ys = message }

and dh_params_unpack { Core.dh_p ; dh_g ; dh_Ys } =
  let z_of_cs = Numeric.Z.of_cstruct_be ?bits:None in
  ({ Dh.p = z_of_cs dh_p ; gg = z_of_cs dh_g ; q = None }, dh_Ys)

let dh_shared group secret public =
  try Some (Dh.shared group secret public)
  with Dh.Invalid_public_key -> None

module Ciphers = struct

  (* I'm not sure how to get rid of this type, but would welcome a solution *)
  (* only used as result of get_block, which is called by get_cipher below *)
  type keyed = | K_CBC : 'k State.cbc_cipher * (Cstruct.t -> 'k) -> keyed

  let get_block = function
    | TRIPLE_DES_EDE_CBC ->
        let open Cipher_block.DES in
        K_CBC ( (module CBC : Cipher_block.T.CBC with type key = CBC.key),
                CBC.of_secret )

    | AES_128_CBC ->
        let open Cipher_block.AES in
        K_CBC ( (module CBC : Cipher_block.T.CBC with type key = CBC.key),
                CBC.of_secret )

    | AES_256_CBC ->
        let open Cipher_block.AES in
        K_CBC ( (module CBC : Cipher_block.T.CBC with type key = CBC.key),
                CBC.of_secret )

  let get_cipher ~secret ~hmac_secret ~iv_mode ~nonce = function
    | Stream (RC4_128, hmac) ->
        let open Cipher_stream in
        let cipher = (module ARC4 : Cipher_stream.T with type key = ARC4.key) in
        let cipher_secret = ARC4.of_secret secret in
        State.(Stream { cipher ; cipher_secret ; hmac ; hmac_secret })

    | Block (cipher, hmac) ->
       ( match get_block cipher with
         | K_CBC (cipher, sec) ->
            let cipher_secret = sec secret in
            State.(CBC { cipher ; cipher_secret ; iv_mode ; hmac ; hmac_secret })
       )

    | AEAD cipher ->
       let open Cipher_block.AES in
       let cipher = (module CCM : Cipher_block.T.CCM with type key = CCM.key) in
       let cipher_secret = CCM.of_secret ~maclen:16 secret in
       State.(CCM { cipher ; cipher_secret ; nonce })
end

let digest_eq fn ~target cs =
  Utils.Cs.equal target (Hash.digest fn cs)

let sequence_buf seq =
  let open Cstruct in
  let buf = create 8 in
  BE.set_uint64 buf 0 seq ;
  buf

let pseudo_header seq ty (v_major, v_minor) length =
  let open Cstruct in
  let prefix = create 5 in
  set_uint8 prefix 0 (Packet.content_type_to_int ty);
  set_uint8 prefix 1 v_major;
  set_uint8 prefix 2 v_minor;
  BE.set_uint16 prefix 3 length;
  sequence_buf seq <+> prefix

(* MAC used in TLS *)
let mac hash key pseudo_hdr data =
  Hash.mac hash ~key (pseudo_hdr <+> data)

let cbc_block (type a) cipher =
  let module C = (val cipher : Cipher_block.T.CBC with type key = a) in C.block_size

let encrypt_stream (type a) ~cipher ~key data =
  let module C = (val cipher : Cipher_stream.T with type key = a) in
  let { C.message ; key } = C.encrypt ~key data in
  (message, key)

let decrypt_stream (type a) ~cipher ~key data =
  let module C = (val cipher : Cipher_stream.T with type key = a) in
  let { C.message ; key } = C.decrypt ~key data in
  (message, key)


(* crazy CBC padding and unpadding for TLS *)
let cbc_pad ~block data =
  let open Cstruct in

  (* 1 is the padding length, encoded as 8 bit at the end of the fragment *)
  let len = 1 + len data in
  (* we might want to add additional blocks of padding *)
  let padding_length = block - (len mod block) in
  (* 1 is again padding length field *)
  let cstruct_len = padding_length + 1 in
  let pad = create cstruct_len in
  for i = 0 to pred cstruct_len do
    set_uint8 pad i padding_length
  done;
  pad

let cbc_unpad ~block data =
  let open Cstruct in

  let len = len data in
  let padlen = get_uint8 data (pred len) in
  let (res, pad) = split data (len - padlen - 1) in

  let rec check = function
    | i when i > padlen -> true
    | i -> (get_uint8 pad i = padlen) && check (succ i) in

  try
    if check 0 then Some res else None
  with Invalid_argument _ -> None

let encrypt_ccm (type a) ~cipher ~key ~nonce ~adata data =
  let module C = (val cipher : Cipher_block.T.CCM with type key = a) in
  C.encrypt ~key ~nonce ~adata data

let decrypt_ccm (type a) ~cipher ~key ~nonce ~adata data =
  let module C = (val cipher : Cipher_block.T.CCM with type key = a) in
  C.decrypt ~key ~nonce ~adata data

let encrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : Cipher_block.T.CBC with type key = a) in
  let { C.message ; iv } =
    C.encrypt ~key ~iv (data <+> cbc_pad C.block_size data) in
  (message, iv)

let decrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : Cipher_block.T.CBC with type key = a) in
  try
    let { C.message ; iv } = C.decrypt ~key ~iv data in
    match cbc_unpad C.block_size message with
    | Some res -> Some (res, iv)
    | None     -> None
  with
  (* XXX Catches data mis-alignment. Get a more specific exn from nocrypto. *)
  (* We _don't_ leak block size now because we catch misalignment only while
   * decrypting the last block. *)
  | Invalid_argument _ -> None
