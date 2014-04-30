
open Nocrypto
open Nocrypto.Common
open Nocrypto.Hash

open Ciphersuite


let (<>) = Utils.cs_append

(* XXX todo :D *)
let () = Rng.reseed (Cstruct.of_string "\001\002\003\004")

let halve secret =
  let size = Cstruct.len secret in
  let half = size - size / 2 in
  Cstruct.(sub secret 0 half, sub secret (size - half) half)

let rec p_hash (hmac, hmac_n) key seed len =
  let rec expand a to_go =
    let res = hmac ~key (a <> seed) in
    if to_go > hmac_n then
      res <> expand (hmac ~key a) (to_go - hmac_n)
    else Cstruct.sub res 0 to_go
  in
  expand (hmac ~key seed) len

let pseudo_random_function version len secret label seed =
  let labelled = Cstruct.of_string label <> seed in
  let open Core in
  match version with
  | TLS_1_2           ->
     p_hash (SHA256.hmac, 32) secret labelled len
  | TLS_1_1 | TLS_1_0 ->
     let (s1, s2) = halve secret in
     let md5 = p_hash (MD5.hmac, 16) s1 labelled len
     and sha = p_hash (SHA1.hmac, 20) s2 labelled len in
     Cs.xor md5 sha

let generate_master_secret version pre_master_secret seed =
  pseudo_random_function version 48 pre_master_secret "master secret" seed

let key_block version len master_secret seed =
  pseudo_random_function version len master_secret "key expansion" seed

let finished version master_secret label ps =
  let data = Utils.cs_appends ps in
  let open Core in
  match version with
  | TLS_1_0 | TLS_1_1 -> let seed = MD5.digest data <> SHA1.digest data in
                         pseudo_random_function version 12 master_secret label seed
  | TLS_1_2 -> let seed = SHA256.digest data in
               pseudo_random_function version 12 master_secret label seed

let padPKCS1_and_signRSA key msg =

  (* XXX XXX temp *)
  let len = Rsa.priv_bits key / 8 in

  (* inspiration from RFC3447 EMSA-PKCS1-v1_5 and rsa_sign.c from OpenSSL *)
  (* also ocaml-ssh kex.ml *)
  (* msg.length must be 36 (16 MD5 + 20 SHA1) in TLS-1.0/1.1! *)
  let mlen = Cstruct.len msg in
  let padlen = len - mlen in
  if padlen > 3 then
    let out = Cstruct.create len in
    Cstruct.set_uint8 out 0 0;
    Cstruct.set_uint8 out 1 1;
    for i = 2 to (padlen - 2) do
      Cstruct.set_uint8 out i 0xff;
    done;
    Cstruct.set_uint8 out (pred padlen) 0;
    Cstruct.blit msg 0 out padlen mlen;
    Some (Rsa.decrypt ~key out)
  else
    None

let verifyRSA_and_unpadPKCS1 pubkey data =
  let dat = Rsa.encrypt ~key:pubkey data in
  if (Cstruct.get_uint8 dat 0 = 0) && (Cstruct.get_uint8 dat 1 = 1) then
    let rec ff idx =
      match Cstruct.get_uint8 dat idx with
      | 0    -> Some (succ idx)
      | 0xff -> ff (succ idx)
      | _    -> None
    in
    match ff 2 with
    | Some start -> Some (Cstruct.shift dat start)
    | None       -> None
  else
    None

let padPKCS1_and_encryptRSA pubkey data =
  (* we're supposed to do the following:
     0x00 0x02 <random_not_zero> 0x00 data *)

  (* XXX XXX this is temp. *)
  let msglen = Rsa.pub_bits pubkey / 8 in

  let open Cstruct in
  let padlen = msglen - (len data) in
  let msg = create msglen in

  (* the header 0x00 0x02 *)
  set_uint8 msg 0 0;
  set_uint8 msg 1 2;

  let produce_random () = Rng.generate (2 * padlen) in

  (* the non-zero random *)
  let rec copybyte random = function
    | x when x = pred padlen -> ()
    | n                      ->
       if len random = 0 then
         copybyte (produce_random ()) n
       else
         let rest = shift random 1 in
         match get_uint8 random 0 with
         | 0 -> copybyte rest n
         | r -> set_uint8 msg n r;
                copybyte rest (succ n)
  in
  copybyte (produce_random ()) 2;

  (* footer 0x00 *)
  set_uint8 msg (pred padlen) 0;

  (* merging all together *)
  blit data 0 msg padlen (len data);
  Rsa.encrypt ~key:pubkey msg

let decryptRSA_unpadPKCS1 key msg =
  (* XXX XXX temp *)
  let msglen = Rsa.priv_bits key / 8 in

  let open Cstruct in
  if msglen == len msg then
    let dec = Rsa.decrypt ~key msg in
    let rec check_padding cur start = function
      | 0                  -> let res = get_uint8 dec 0 = 0 in
                              check_padding (res && cur) 1 1
      | 1                  -> let res = get_uint8 dec 1 = 2 in
                              check_padding (res && cur) 2 2
      | n when n >= msglen -> start
      | n                  -> let res = get_uint8 dec n = 0 in
                              let nxt = succ n in
                              match cur, res with
                              | true, true -> check_padding false nxt nxt
                              | x   , _    -> check_padding x start nxt
    in
    let start = check_padding true 0 0 in
    Some (Cstruct.shift dec start)
  else
    None

(* on-the-wire dh_params <-> (group, pub_message) *)
let dh_params_pack group message =
  let (p, g) = DH.to_cstruct group in
  { Core.dh_p = p ; dh_g = g ; dh_Ys = message }

and dh_params_unpack { Core.dh_p ; dh_g ; dh_Ys } =
  ( DH.group ~p:dh_p ~gg:dh_g (), dh_Ys )


(* XXX *)

(* Stupid boiler before properly exposing proper module types from nocrypto. *)

module type Stream_T = sig
  type key
  type result = { message : Cstruct.t ; key : key }
  val of_secret : Cstruct.t -> key
  val encrypt : key:key -> Cstruct.t -> result
  val decrypt : key:key -> Cstruct.t -> result
end

module type CBC_T = sig
  type key
  type result = { message : Cstruct.t ; iv : Cstruct.t }
  val block_size : int
  val of_secret : Cstruct.t -> key
  val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
  val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
end

module type Hash_T = sig
  val digest  : Cstruct.t -> Cstruct.t
  val digestv : Cstruct.t list -> Cstruct.t
  val hmac    : key:Cstruct.t -> Cstruct.t -> Cstruct.t
  val digest_size : int
end

(* /XXX *)

type 'k stream_cipher = (module Stream_T with type key = 'k)
type 'k cbc_cipher    = (module CBC_T    with type key = 'k)
type hash_fn          = (module Hash_T)

module Ciphers = struct

  (* XXX partial *)
  let get_hash = function
    | MD5    -> (module Hash.MD5    : Hash_T)
    | SHA    -> (module Hash.SHA1   : Hash_T)
(* XXX needs either divorcing hash selection from hmac selection, or a bit of
 * structural subtyping magic as SHA224 has no defined HMAC. (?) *)
(*     | SHA224 -> (module Hash.SHA224 : Hash_T) *)
    | SHA256 -> (module Hash.SHA256 : Hash_T)
    | SHA384 -> (module Hash.SHA384 : Hash_T)
    | SHA512 -> (module Hash.SHA512 : Hash_T)

  type keyed =
    | K_Stream : 'k stream_cipher * 'k -> keyed
    | K_CBC    : 'k cbc_cipher    * 'k -> keyed

  (* XXX partial *)
  let get_cipher ~secret = function

    | RC4_128 ->
        let open Stream in
        K_Stream ( (module ARC4 : Stream_T with type key = ARC4.key),
                   ARC4.of_secret secret )

    | TRIPLE_DES_EDE_CBC ->
        let open Block.DES in
        K_CBC ( (module CBC : CBC_T with type key = CBC.key),
                CBC.of_secret secret )

    | AES_128_CBC ->
        let open Block.AES in
        K_CBC ( (module CBC : CBC_T with type key = CBC.key),
                CBC.of_secret secret )

    | AES_256_CBC ->
        let open Block.AES in
        K_CBC ( (module CBC : CBC_T with type key = CBC.key),
                CBC.of_secret secret )
end

let hash hash_ctor cs =
  let hasht = Ciphers.get_hash hash_ctor in
  let module H = (val hasht : Hash_T) in
  H.digest cs

let hash_eq hash_ctor ~target cs =
  Utils.cs_eq target (hash hash_ctor cs)

(* Decoder + project asn algos into hashes we understand. *)
let pkcs1_digest_info_of_cstruct cs =
  match Asn_grammars.pkcs1_digest_info_of_cstruct cs with
  | None -> None
  | Some (asn_algo, digest) ->
      match Ciphersuite.asn_to_hash_algorithm asn_algo with
      | Some hash -> Some (hash, digest)
      | None      -> None

let pkcs1_digest_info_to_cstruct hashalgo data =
  let signature = hash hashalgo data in
  match Ciphersuite.hash_algorithm_to_asn hashalgo with
  | Some x -> Some (Asn_grammars.pkcs1_digest_info_to_cstruct (x, signature))
  | None   -> None

let mac (hash, secret) seq ty (v_major, v_minor) data =
  let open Cstruct in

  let prefix = create 13
  and len = len data in

  BE.set_uint64 prefix 0 seq;
  set_uint8 prefix 8 (Packet.content_type_to_int ty);
  set_uint8 prefix 9 v_major;
  set_uint8 prefix 10 v_minor;
  BE.set_uint16 prefix 11 len;

  let module H = (val hash : Hash_T) in
  H.hmac ~key:secret (prefix <> data)


let cbc_block (type a) cipher =
  let module C = (val cipher : CBC_T with type key = a) in C.block_size

let digest_size h =
  let module H = (val h : Hash_T) in H.digest_size


let encrypt_stream (type a) ~cipher ~key data =
  let module C = (val cipher : Stream_T with type key = a) in
  let { C.message ; key } = C.encrypt ~key data in
  (message, key)

let decrypt_stream (type a) ~cipher ~key data =
  let module C = (val cipher : Stream_T with type key = a) in
  let { C.message ; key } = C.decrypt ~key data in
  (message, key)


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
  let module C = (val cipher : CBC_T with type key = a) in
  let { C.message ; iv } =
    C.encrypt ~key ~iv (data <> cbc_pad C.block_size data) in
  (message, iv)

let decrypt_cbc (type a) ~cipher ~key ~iv data =
  let module C = (val cipher : CBC_T with type key = a) in
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
