open Nocrypto
open Nocrypto.Uncommon
open Nocrypto.Hash

open Core
open State

let (<+>) = Utils.Cs.(<+>)

let halve secret =
  let size = Cstruct.len secret in
  let half = size - size / 2 in
  Cstruct.(sub secret 0 half, sub secret (size - half) half)

let rec p_hash (hmac, hmac_n) key seed len =
  let rec expand a to_go =
    let res = hmac ~key (a <+> seed) in
    if to_go > hmac_n then
      res <+> expand (hmac ~key a) (to_go - hmac_n)
    else Cstruct.sub res 0 to_go
  in
  expand (hmac ~key seed) len

let pseudo_random_function version len secret label seed =
  let labelled = Cstruct.of_string label <+> seed in
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
  let data = Utils.Cs.appends ps in
  match version with
  | TLS_1_0 | TLS_1_1 ->
     let seed = MD5.digest data <+> SHA1.digest data in
     pseudo_random_function version 12 master_secret label seed
  | TLS_1_2 ->
     let seed = SHA256.digest data in
     pseudo_random_function version 12 master_secret label seed

let divide_keyblock key mac iv buf =
  let open Cstruct in
  let c_mac, rt0 = split buf mac in
  let s_mac, rt1 = split rt0 mac in
  let c_key, rt2 = split rt1 key in
  let s_key, rt3 = split rt2 key in
  let c_iv , s_iv = split rt3 iv
  in
  (c_mac, s_mac, c_key, s_key, c_iv, s_iv)

let make_context cipher version master server_random client_random =
  let pp = Ciphersuite.ciphersuite_privprot cipher in

  let c_mac, s_mac, c_key, s_key, c_iv, s_iv =
    let iv_l = match version with
      | TLS_1_0 -> Some ()
      | _       -> None
    in
    let key_len, iv_len, mac_len = Ciphersuite.key_length iv_l pp in
    let kblen = 2 * key_len + 2 * mac_len + 2 * iv_len
    and rand = server_random <+> client_random
    in
    let keyblock = key_block version kblen master rand in
    divide_keyblock key_len mac_len iv_len keyblock
  in

  let context cipher_k iv mac_k =
    let open Crypto.Ciphers in
    let cipher_st =
      let iv_mode = match version with
        | TLS_1_0 -> Iv iv
        | _       -> Random_iv
      in
      get_cipher ~secret:cipher_k ~hmac_secret:mac_k ~iv_mode ~nonce:iv pp
    and sequence = 0L in
    { cipher_st ; sequence }
  in

  let c_context = context c_key c_iv c_mac
  and s_context = context s_key s_iv s_mac in

  (c_context, s_context)

let initialise_crypto_ctx version session premaster =
  let client_random = session.client_random
  and server_random = session.server_random
  and cipher = session.ciphersuite
  in

  let master = generate_master_secret version premaster
                (client_random <+> server_random) in

  let cc, sc = make_context cipher version master server_random client_random in
  (cc, sc, master)
