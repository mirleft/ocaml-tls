
open Nocrypto
open Nocrypto.Common
open Nocrypto.Hash

open Ciphersuite
open Packet

let (<+>) = Utils.Cs.(<+>)


(* on-the-wire dh_params <-> (group, pub_message) *)
let dh_params_pack group message =
  let (p, g) = DH.to_cstruct group in
  { Core.dh_p = p ; dh_g = g ; dh_Ys = message }

and dh_params_unpack { Core.dh_p ; dh_g ; dh_Ys } =
  ( DH.group ~p:dh_p ~gg:dh_g (), dh_Ys )

let dh_shared group secret public =
  try Some (DH.shared group secret public)
  with DH.Invalid_public_key -> None


type 'k stream_cipher = (module Stream.T    with type key = 'k)
type 'k cbc_cipher    = (module Block.T_CBC with type key = 'k)
type hash_fn          = (module Hash.T_MAC)

module Ciphers = struct

  (* XXX partial *)
  let get_hash = function
    | MD5    -> (module Hash.MD5    : Hash.T_MAC)
    | SHA    -> (module Hash.SHA1   : Hash.T_MAC)
(* XXX needs either divorcing hash selection from hmac selection, or a bit of
 * structural subtyping magic as SHA224 has no defined HMAC. (?) *)
(*     | SHA224 -> (module Hash.SHA224 : Hash.T_MAC) *)
    | SHA256 -> (module Hash.SHA256 : Hash.T_MAC)
    | SHA384 -> (module Hash.SHA384 : Hash.T_MAC)
    | SHA512 -> (module Hash.SHA512 : Hash.T_MAC)

  type keyed =
    | K_Stream : 'k stream_cipher * 'k -> keyed
    | K_CBC    : 'k cbc_cipher    * 'k -> keyed

  (* XXX partial *)
  let get_cipher ~secret = function

    | RC4_128 ->
        let open Stream in
        K_Stream ( (module ARC4 : Stream.T with type key = ARC4.key),
                   ARC4.of_secret secret )

    | TRIPLE_DES_EDE_CBC ->
        let open Block.DES in
        K_CBC ( (module CBC : Block.T_CBC with type key = CBC.key),
                CBC.of_secret secret )

    | AES_128_CBC ->
        let open Block.AES in
        K_CBC ( (module CBC : Block.T_CBC with type key = CBC.key),
                CBC.of_secret secret )

    | AES_256_CBC ->
        let open Block.AES in
        K_CBC ( (module CBC : Block.T_CBC with type key = CBC.key),
                CBC.of_secret secret )
end

let hash hash_ctor cs =
  let hasht = Ciphers.get_hash hash_ctor in
  let module H = (val hasht : Hash.T_MAC) in
  H.digest cs

let hash_eq hash_ctor ~target cs =
  Utils.Cs.equal target (hash hash_ctor cs)

(* MAC used in TLS *)
let mac (hash, secret) seq ty (v_major, v_minor) data =
  let open Cstruct in

  let prefix = create 13
  and len = len data in

  BE.set_uint64 prefix 0 seq;
  set_uint8 prefix 8 (Packet.content_type_to_int ty);
  set_uint8 prefix 9 v_major;
  set_uint8 prefix 10 v_minor;
  BE.set_uint16 prefix 11 len;

  let module H = (val hash : Hash.T_MAC) in
  H.hmac ~key:secret (prefix <+> data)

(* XXX Make these two go away by controling the number of ways to represent the
 * hash algorithm... *)

let pkcs1_digest_info_of_cstruct cs =
  match Asn_grammars.pkcs1_digest_info_of_cstruct cs with
  | None -> None
  | Some (asn_algo, digest) ->
      match hash_algorithm_of_tag asn_algo with
      | Some hash -> Some (hash, digest)
      | None      -> None

and pkcs1_digest_info_to_cstruct hashalgo data =
  let signature = hash hashalgo data in
  match tag_of_hash_algorithm hashalgo with
  | Some x -> Some (Asn_grammars.pkcs1_digest_info_to_cstruct (x, signature))
  | None   -> None

let cbc_block (type a) cipher =
  let module C = (val cipher : Block.T_CBC with type key = a) in C.block_size

let digest_size h =
  let module H = (val h : Hash.T_MAC) in H.digest_size


let encrypt_stream (type a) ~cipher ~key data =
  let module C = (val cipher : Stream.T with type key = a) in
  let { C.message ; key } = C.encrypt ~key data in
  (message, key)

let decrypt_stream (type a) ~cipher ~key data =
  let module C = (val cipher : Stream.T with type key = a) in
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
  let module C = (val cipher : Block.T_CBC with type key = a) in
  let { C.message ; iv } =
    C.encrypt ~key ~iv (data <+> cbc_pad C.block_size data) in
  (message, iv)

let decrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : Block.T_CBC with type key = a) in
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
