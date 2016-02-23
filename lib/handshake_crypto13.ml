open Nocrypto

let (<+>) = Utils.Cs.(<+>)

let trace tag cs = Tracing.cs ~tag:("crypto " ^ tag) cs

let expand_label hash prk label hashvalue length =
  let info =
    let len = Cstruct.create 2 in
    Cstruct.BE.set_uint16 len 0 length ;
    let label = Cstruct.of_string ("TLS 1.3, " ^ label) in
    let llen = Cstruct.create 1 in
    Cstruct.set_uint8 llen 0 (Cstruct.len label) ;
    let hashlen = Cstruct.create 1 in
    Cstruct.set_uint8 hashlen 0 (Cstruct.len hashvalue) ;
    len <+> llen <+> label <+> hashlen <+> hashvalue
  in
  let key = Hkdf.expand ~hash ~prk ~info length in
  trace label key ;
  key

let pp_hash_k_n ciphersuite =
  let open Ciphersuite in
  let pp = privprot13 ciphersuite
  and hash = hash_of ciphersuite
  in
  let k, n = kn pp in
  (pp, hash, k, n)

let ctx cs lbl sec log =
  let pp, hash, k, n = pp_hash_k_n cs in
  let key purpose len =
    expand_label hash sec (lbl ^ purpose) log len
  in
  let ctx wr iv =
    let secret = key wr k
    and nonce = key iv n
    in
    { State.sequence = 0L ; cipher_st = Crypto.Ciphers.get_aead ~secret ~nonce pp }
  in
  (ctx "server write key" "server write iv",
   ctx "client write key" "client write iv")

let hs_ctx cs log es =
  let hash = Ciphersuite.hash_of cs in
  let xes = Hkdf.extract ~hash es in
  trace "xes" xes ;
  let log = Hash.digest hash log in
  ctx cs "handshake key expansion, " xes log

let traffic_secret cs master_secret log =
  let hash = Ciphersuite.hash_of cs in
  let d = Hash.digest hash log
  and l = Hash.digest_size hash
  in
  expand_label hash master_secret "traffic secret" d l

let resumption_secret cs master_secret log =
  let hash = Ciphersuite.hash_of cs in
  let d = Hash.digest hash log
  and l = Hash.digest_size hash
  in
  expand_label hash master_secret "resumption master secret" d l

let app_ctx cs log traffic_secret =
  let hash = Ciphersuite.hash_of cs in
  let log = Hash.digest hash log in
  ctx cs "application data key expansion, " traffic_secret log

let master_secret cs es ss hlog =
  let hash = Ciphersuite.hash_of cs in
  let module H = (val (Nocrypto.Hash.module_of hash)) in
  let module HK = Hkdf.Make(H) in
  let hlog = H.digest hlog in
  let xss = HK.extract ss
  and xes = HK.extract es
  in
  trace "xss" xss ;
  trace "xes" xes ;
  let l = H.digest_size in
  let mss = expand_label hash xss "expanded static secret" hlog l in
  let mes = expand_label hash xes "expanded ephemeral secret" hlog l in
  let ms = HK.extract ~salt:mss mes in
  trace "master secret" ms ;
  ms

let finished cs master_secret server data =
  let hash = Ciphersuite.hash_of cs in
  let label = if server then "server finished" else "client finished" in
  let key = expand_label hash master_secret label (Cstruct.create 0) (Hash.digest_size hash) in
  Hash.mac hash ~key (Hash.digest hash data)

