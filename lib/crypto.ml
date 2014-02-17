

let p_md5 len secret a seed =
  let res = HMAC_md5 secret (a ^ seed) in
  if len > 16 then
    res ^ (p_md5 (len - 16) secret res seed)
  else
    res

let p_sha1 len secret a seed =
  let res = HMAC_sha secret (a ^ seed) in
  if len > 16 then
    res ^ (p_sha1 (len - 20) secret res seed)
  else
    res

let pseudo_random_function len sec secret label seed =
  let s1, s2 = halve secret in
  let md5 = p_md5 len s1 seed (label ^ seed) in
  let sha = p_sha len s2 seed (label ^ seed) in
  xor md5 sha

let generate_master_secret =
  pseudo_random_function 48 pre_master_secret "master secret" (client_random ^ server_random)

let key_block =
  pseudo_random_function master_secret "key expansion" (server_random ^ client_random) (* till enough output (mac * 2 + key * 2 + iv * 2) *)


