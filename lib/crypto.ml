
open Nocrypto
open Nocrypto.Common
open Nocrypto.Hash

open Ciphersuite


let (<>) = Utils.cs_append

(* XXX todo :D *)
let () = Rng.reseed (Cstruct.of_string "\001\002\003\004")

let halve secret =
  let len  = Cstruct.len secret in
  let half = len - len / 2 in
  (Cstruct.sub secret 0 half, Cstruct.sub secret (len - half) half)

let rec p_hash (hmac, hmac_n) key seed len =
  let rec expand a to_go =
    let res = hmac ~key (a <> seed) in
    if to_go > hmac_n then
      res <> expand (hmac ~key a) (to_go - hmac_n)
    else Cstruct.sub res 0 to_go
  in
  expand (hmac ~key seed) len

let pseudo_random_function len secret label seed =
  let (s1, s2) = halve secret
  and labelled = Cstruct.of_string label <> seed in
  let md5 = p_hash (MD5.hmac, 16) s1 labelled len
  and sha = p_hash (SHA1.hmac, 20) s2 labelled len in
  CS.xor md5 sha

let generate_master_secret pre_master_secret seed =
  pseudo_random_function 48 pre_master_secret "master secret" seed

let key_block len master_secret seed =
  pseudo_random_function len master_secret "key expansion" seed

let finished master_secret label ps =
  let data = Utils.cs_appends ps in
  let seed = MD5.digest data <> SHA1.digest data in
  pseudo_random_function 12 master_secret label seed

let padPKCS1_and_signRSA key msg =

  (* XXX XXX temp *)
  let len = Rsa.priv_bits key / 8 in

  (* inspiration from RFC3447 EMSA-PKCS1-v1_5 and rsa_sign.c from OpenSSL *)
  (* also ocaml-ssh kex.ml *)
  (* msg.length must be 36 (16 MD5 + 20 SHA1)! *)
  let mlen = Cstruct.len msg in
  let padlen = len - mlen in
  if (padlen > 3) && (mlen = 36) then
    let out = Cstruct.create len in
    Cstruct.set_uint8 out 0 0;
    Cstruct.set_uint8 out 1 1;
    for i = 2 to (padlen - 2) do
      Cstruct.set_uint8 out i 0xff;
    done;
    Cstruct.set_uint8 out (padlen - 1) 0;
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

  let len = Rsa.pub_bits pubkey / 8 in
  let padlen = len - (Cstruct.len data) in
  let pad = Cstruct.create len in
  Cstruct.set_uint8 pad 0 0;
  Cstruct.set_uint8 pad 1 2;
  for i = 2 to padlen - 2 do
    Cstruct.set_uint8 pad i 0xAA; (* TODO: might use better random *)
  done;
  Cstruct.set_uint8 pad (padlen - 1) 0;
  Cstruct.blit data 0 pad padlen (Cstruct.len data);
  Rsa.encrypt ~key:pubkey pad

let decryptRSA_unpadPKCS key msg =
  (* might fail if len msg > keysize! *)
  let dec = Rsa.decrypt ~key msg in
  (* we're branching -- do same computation in both branches! *)
  if (Cstruct.get_uint8 dec 0 = 0) && (Cstruct.get_uint8 dec 1 = 2) then
    let rec not0 idx =
      match Cstruct.get_uint8 dec idx with
      | 0 -> succ idx
      | _ -> not0 (succ idx)
    in
    let start = not0 2 in
    Some (Cstruct.shift dec start)
  else
    None

(* on-the-wire dh_params <-> (group, pub_message) *)
let dh_params_pack group message =
  let (p, g) = DH.to_cstruct group in
  { Core.dh_p = p ; dh_g = g ; dh_Ys = message }

and dh_params_unpack { Core.dh_p ; dh_g ; dh_Ys } =
  ( DH.group ~p:dh_p ~gg:dh_g (), dh_Ys )

let hmac = function
  | MD5 -> MD5.hmac
  | SHA -> SHA1.hmac

let signature mac secret n ty (major, minor) data =
  let open Cstruct in

  let prefix = create 13
  and len = len data in

  BE.set_uint64 prefix 0 n;
  set_uint8 prefix 8 (Packet.content_type_to_int ty);
  set_uint8 prefix 9 major;
  set_uint8 prefix 10 minor;
  BE.set_uint16 prefix 11 len;

  hmac mac ~key:secret (prefix <> data)

let prepare_arcfour : Cstruct.t -> Cryptokit.Stream.stream_cipher =
  fun key ->
    new Cryptokit.Stream.arcfour (Cstruct.copy key 0 (Cstruct.len key))

(* encryption and decryption is the same, thus "crypt" *)
let crypt_stream : Cryptokit.Stream.stream_cipher -> Cstruct.t -> Cstruct.t
  = fun cipher decrypted ->
      let len = Cstruct.len decrypted in
      let encrypted = String.create len in
      let dec = Cstruct.copy decrypted 0 len in
      cipher#transform dec 0 encrypted 0 len;
      Cstruct.of_string encrypted

let last_block (cipher : encryption_algorithm) data =
  let bs = encryption_algorithm_block_size cipher in
  let blocks = (Cstruct.len data) / bs in
  Cstruct.sub data ((blocks - 1) * bs) bs

let pad (enc : encryption_algorithm) data =
  let bs = encryption_algorithm_block_size enc in
  (* 1 is the padding length, encoded as 8 bit at the end of the fragment *)
  let len = 1 + Cstruct.len data in
  (* we might want to add additional blocks of padding *)
  let padding_length = bs - (len mod bs) in
  (* 1 is again padding length field *)
  let cstruct_len = padding_length + 1 in
  let pad = Cstruct.create cstruct_len in
  for i = 0 to (cstruct_len - 1) do
    Cstruct.set_uint8 pad i padding_length
  done;
  pad

let unpad (enc : encryption_algorithm) data =
  let open Cstruct in

  let bs  = encryption_algorithm_block_size enc
  and len = len data in
  let padlen = get_uint8 data (len - 1) in
  let (res, pad) = split data (len - padlen - 1) in

  let rec check = function
    | i when i = padlen -> Some res
    | i -> if get_uint8 pad i = padlen then check (succ i) else None
  in check 0

(* in: algo, secret, iv, data
   out: [padded]encrypted data *)
let encrypt_block (cipher : encryption_algorithm) sec iv data =
  let padded = data <> pad cipher data in
  match cipher with
  | TRIPLE_DES_EDE_CBC ->
      Block.DES.CBC.((encrypt ~key:(of_secret sec) ~iv padded).message)

(* in: algo, secret, iv, data
   out: [unpadded]decrypted data *)
let decrypt_block (cipher : encryption_algorithm) sec iv data =
  let len = Cstruct.len data in
  try
    let dec = match cipher with
      | TRIPLE_DES_EDE_CBC ->
          Block.DES.CBC.((decrypt ~key:(of_secret sec) ~iv data).message)
    in
    unpad cipher dec
  with
  (* we leak block size information (due to faster processing here)
     do we leak anything else? *)
  | Invalid_argument _ -> None
  (* XXX Catches both data mis-alignment and empty.
   * Get a more specific exn from Nocrypto. *)
