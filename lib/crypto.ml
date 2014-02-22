
let hmac_md5 sec = Cryptokit.(hash_string (MAC.hmac_md5 sec))
let hmac_sha sec = Cryptokit.(hash_string (MAC.hmac_sha1 sec))

let rec p_hash (hmac, hmac_n) secret seed len =
  let rec expand a to_go =
    let res = hmac secret (a ^ seed) in
    if to_go > hmac_n then
      res ^ expand (hmac secret a) (to_go - hmac_n)
    else String.sub res 0 to_go
  in
  expand (hmac secret seed) len

let halve secret =
  let len  = String.length secret in
  let half = len - len / 2 in
  String.( sub secret 0 half, sub secret (len - half) half )

let pseudo_random_function len secret label seed =
  let (s1, s2) = halve secret in
  let md5 = p_hash (hmac_md5, 16) s1 (label ^ seed) len
  and sha = p_hash (hmac_sha, 20) s2 (label ^ seed) len in
  Cryptokit.xor_string md5 0 sha 0 len ;
  sha

let generate_master_secret pre_master_secret seed =
  pseudo_random_function 48 pre_master_secret "master secret" seed

let key_block len master_secret seed =
  pseudo_random_function len master_secret "key expansion" seed

let finished master_secret label data =
  let md5 = Cryptokit.(hash_string (Hash.md5 ()) data) in
  let sha1 = Cryptokit.(hash_string (Hash.sha1 ()) data) in
  pseudo_random_function 12 master_secret label (md5 ^ sha1)

let encryptRSA key msg =
  Cryptokit.RSA.encrypt key msg

let decryptRSA key msg =
  Cryptokit.RSA.decrypt key msg

