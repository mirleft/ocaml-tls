
open Nocrypto
open Nocrypto.Uncommon
open Nocrypto.Hash

open Ciphersuite
open Packet

let (<+>) = Utils.Cs.(<+>)


(* on-the-wire dh_params <-> (group, pub_message) *)
let dh_params_pack group message =
  let (p, g) = Dh.to_cstruct group in
  { Core.dh_p = p ; dh_g = g ; dh_Ys = message }

and dh_params_unpack { Core.dh_p ; dh_g ; dh_Ys } =
  ( Dh.group ~p:dh_p ~gg:dh_g (), dh_Ys )

let dh_shared group secret public =
  try Some (Dh.shared group secret public)
  with Dh.Invalid_public_key -> None


type 'k stream_cipher = (module Cipher_stream.T    with type key = 'k)
type 'k cbc_cipher    = (module Cipher_block.T_CBC with type key = 'k)

module Ciphers = struct

  type keyed =
    | K_Stream : 'k stream_cipher * 'k -> keyed
    | K_CBC    : 'k cbc_cipher    * 'k -> keyed

  (* XXX partial *)
  let get_cipher ~secret = function

    | RC4_128 ->
        let open Cipher_stream in
        K_Stream ( (module ARC4 : Cipher_stream.T with type key = ARC4.key),
                   ARC4.of_secret secret )

    | TRIPLE_DES_EDE_CBC ->
        let open Cipher_block.DES in
        K_CBC ( (module CBC : Cipher_block.T_CBC with type key = CBC.key),
                CBC.of_secret secret )

    | AES_128_CBC ->
        let open Cipher_block.AES in
        K_CBC ( (module CBC : Cipher_block.T_CBC with type key = CBC.key),
                CBC.of_secret secret )

    | AES_256_CBC ->
        let open Cipher_block.AES in
        K_CBC ( (module CBC : Cipher_block.T_CBC with type key = CBC.key),
                CBC.of_secret secret )
end

let digest_eq fn ~target cs =
  Utils.Cs.equal target (Hash.digest fn cs)

(* MAC used in TLS *)
let mac (hash, key) seq ty (v_major, v_minor) data =
  let open Cstruct in

  let prefix = create 13
  and len = len data in

  BE.set_uint64 prefix 0 seq;
  set_uint8 prefix 8 (Packet.content_type_to_int ty);
  set_uint8 prefix 9 v_major;
  set_uint8 prefix 10 v_minor;
  BE.set_uint16 prefix 11 len;

  Hash.mac hash ~key (prefix <+> data)

let cbc_block (type a) cipher =
  let module C = (val cipher : Cipher_block.T_CBC with type key = a) in C.block_size

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


let encrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : Cipher_block.T_CBC with type key = a) in
  let { C.message ; iv } =
    C.encrypt ~key ~iv (data <+> cbc_pad C.block_size data) in
  (message, iv)

let decrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : Cipher_block.T_CBC with type key = a) in
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
