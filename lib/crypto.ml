
open Nocrypto
open Nocrypto.Common
open Nocrypto.Hash

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

let signRSA key msg =
  let input = Cstruct.copy msg 0 (Cstruct.len msg) in
  let res = Cryptokit.RSA.sign key input in
  Cstruct.of_string res

let padPKCS1_and_signRSA key msg =
  (* inspiration from RFC3447 EMSA-PKCS1-v1_5 and rsa_sign.c from OpenSSL *)
  (* also ocaml-ssh kex.ml *)
  (* msg.length must be 36 (16 MD5 + 20 SHA1)! *)
  let mlen = Cstruct.len msg in
  let len = Cryptokit.RSA.(key.size / 8) in
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
    Some (signRSA key out)
  else
    None

let verifyRSA key msg =
  let input = Cstruct.copy msg 0 (Cstruct.len msg) in
  let res = Cryptokit.RSA.unwrap_signature key input in
  Cstruct.of_string res

let verifyRSA_and_unpadPKCS1 pubkey data =
  let dat = verifyRSA pubkey data in
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

let encryptRSA key msg =
  let input = Cstruct.copy msg 0 (Cstruct.len msg) in
  let res = Cryptokit.RSA.encrypt key input in
  Cstruct.of_string res

let padPKCS1_and_encryptRSA len pubkey data =
  (* we're supposed to do the following:
     0x00 0x02 <random_not_zero> 0x00 data *)
  let padlen = len - (Cstruct.len data) in
  let pad = Cstruct.create len in
  Cstruct.set_uint8 pad 0 0;
  Cstruct.set_uint8 pad 1 2;
  for i = 2 to padlen - 2 do
    Cstruct.set_uint8 pad i 0xAA; (* TODO: might use better random *)
  done;
  Cstruct.set_uint8 pad (padlen - 1) 0;
  Cstruct.blit data 0 pad padlen (Cstruct.len data);
  encryptRSA pubkey pad

let decryptRSA key msg =
  (* might fail if len msg > keysize! *)
  let input = Cstruct.copy msg 0 (Cstruct.len msg) in
  let res = Cryptokit.RSA.decrypt key input in
  Cstruct.of_string res

let decryptRSA_unpadPKCS key msg =
  let dec = decryptRSA key msg in
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
  (* XXX p, g sizing?? *)
  let (p, g) = DH.to_cstruct group in
  { Core.dh_p = p ; dh_g = g ; dh_Ys = message }

and dh_params_unpack { Core.dh_p ; dh_g ; dh_Ys } =
  ( DH.group ~p:dh_p ~gg:dh_g (), dh_Ys )

let hmac = function
  | Ciphersuite.MD5 -> MD5.hmac
  | Ciphersuite.SHA -> SHA1.hmac

let signature : Ciphersuite.hash_algorithm -> Cstruct.t -> int64 -> Packet.content_type -> (int * int) -> Cstruct.t -> Cstruct.t
  = fun mac secret n ty (major, minor) data ->
      let prefix = Cstruct.create 13 in
      let len = Cstruct.len data in
      Cstruct.BE.set_uint64 prefix 0 n;
      Cstruct.set_uint8 prefix 8 (Packet.content_type_to_int ty);
      Cstruct.set_uint8 prefix 9 major;
      Cstruct.set_uint8 prefix 10 minor;
      Cstruct.BE.set_uint16 prefix 11 len;
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

let last_block : Ciphersuite.encryption_algorithm -> Cstruct.t -> Cstruct.t
  = fun cipher data ->
  let bs = Ciphersuite.encryption_algorithm_block_size cipher in
  let blocks = (Cstruct.len data) / bs in
  Cstruct.sub data ((blocks - 1) * bs) bs

let pad : Ciphersuite.encryption_algorithm -> Cstruct.t -> Cstruct.t
  = fun enc data ->
  let bs = Ciphersuite.encryption_algorithm_block_size enc in
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

(* in: algo, secret, iv, data
   out: [padded]encrypted data *)
let encrypt_block : Ciphersuite.encryption_algorithm -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t
  = fun cipher sec iv data ->
      let to_encrypt = data <> (pad cipher data) in
      let cip = match cipher with
        | Ciphersuite.TRIPLE_DES_EDE_CBC ->
           let key = Cstruct.copy sec 0 (Cstruct.len sec) in
           let siv = Cstruct.copy iv 0 (Cstruct.len iv) in
           let cip = new Cryptokit.Block.triple_des_encrypt key in
           new Cryptokit.Block.cbc_encrypt ~iv:siv cip
      in
      let datalen = Cstruct.len to_encrypt in
      let bs = Ciphersuite.encryption_algorithm_block_size cipher in
      let blocks = datalen / bs in
      let enc = String.create (Cstruct.len to_encrypt) in
      let dat = Cstruct.copy to_encrypt 0 datalen in
      for i = 0 to (blocks - 1) do
        cip#transform dat (i * bs) enc (i * bs)
      done;
      Cstruct.of_string enc

(* in: algo, secret, iv, data
   out: [padded]decrypted data *)
let decrypt_block : Ciphersuite.encryption_algorithm -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t option
  = fun cipher sec iv data ->
      let cip = match cipher with
        | Ciphersuite.TRIPLE_DES_EDE_CBC ->
           let key = Cstruct.copy sec 0 (Cstruct.len sec) in
           let siv = Cstruct.copy iv 0 (Cstruct.len iv) in
           let cip = new Cryptokit.Block.triple_des_decrypt key in
           new Cryptokit.Block.cbc_decrypt ~iv:siv cip
      in
      let datalen = Cstruct.len data in
      let bs = Ciphersuite.encryption_algorithm_block_size cipher in
      match datalen mod bs with
      | 0 ->
         (* datalen > 0 *)
         let blocks = datalen / bs in
         let dec = String.create datalen in
         let dat = Cstruct.copy data 0 datalen in
         for i = 0 to (blocks - 1) do
           cip#transform dat (i * bs) dec (i * bs)
         done;
         let result = Cstruct.of_string dec in
         let padlen = Cstruct.get_uint8 result (datalen - 1) in
         let res, padding = Cstruct.split result (datalen - padlen - 1) in
         let correct_padding =
           Cstruct.fold (fun acc data -> if Cstruct.get_uint8 data 0 == padlen then
                                           acc
                                         else
                                           false)
                        (Cstruct.iter (fun buf -> Some 1) (fun buf -> buf) padding) true
         in
         if correct_padding then
           Some res
         else
           None
      | _ ->
         (* we leak block size information (due to faster processing here) *)
         (* do we leak anything else? *)
         None
