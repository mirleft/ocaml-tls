
let hmac_md5 sec see = Cryptokit.hash_string (Cryptokit.MAC.hmac_md5 sec) see
let hmac_sha sec see = Cryptokit.hash_string (Cryptokit.MAC.hmac_sha1 sec) see

let rec p_md5 len secret a seed =
  let res = hmac_md5 secret (a ^ seed) in
  if len > 16 then
    res ^ (p_md5 (len - 16) secret res seed)
  else
    res

let rec p_sha len secret a seed =
  let res = hmac_sha secret (a ^ seed) in
  if len > 16 then
    res ^ (p_sha (len - 20) secret res seed)
  else
    res

let halve secret =
  let len = String.length secret in
  let half = int_of_float (ceil ((float_of_int len) /. 2.)) in
  Printf.printf "length half is %d, len %d\n" half len;
  (String.sub secret 0 half,
   String.sub secret (len - half) half)

let pseudo_random_function len secret label seed =
  let s1, s2 = halve secret in
  let md5 = p_md5 len s1 seed (label ^ seed) in
  let sha = p_sha len s2 seed (label ^ seed) in
  Cryptokit.xor_string md5 0 sha 0 len;
  sha

let generate_master_secret pre_master_secret seed =
  pseudo_random_function 48 pre_master_secret "master secret" seed

let key_block len master_secret seed =
  pseudo_random_function len master_secret "key expansion" seed


