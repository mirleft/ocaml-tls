open Core
open Nocrypto

let (<+>) = Utils.Cs.(<+>)

type own_cert = Certificate.certificate * RSA.priv

(* some config parameters *)
type config = {
  ciphers           : Ciphersuite.ciphersuite list ;
  protocol_versions : tls_version list ;
  hashes            : Ciphersuite.hash_algorithm list ;
  (* signatures        : Packet.signature_algorithm_type list ; *)
  rekeying          : bool ;
  validator         : X509.Validator.t option ;
  peer_name         : string option ;
  own_certificate   : own_cert option ;
}

let default_config = {
  (* ordered list (regarding preference) of supported cipher suites *)
  ciphers = Ciphersuite.([ TLS_RSA_WITH_AES_256_CBC_SHA ;
                           TLS_DHE_RSA_WITH_AES_256_CBC_SHA ;
                           TLS_RSA_WITH_AES_128_CBC_SHA ;
                           TLS_DHE_RSA_WITH_AES_128_CBC_SHA ;
                           TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
                           TLS_RSA_WITH_3DES_EDE_CBC_SHA ;
                           TLS_RSA_WITH_RC4_128_SHA ;
                           TLS_RSA_WITH_RC4_128_MD5 ]) ;
  (* ordered list of decreasing protocol versions *)
  protocol_versions = [ TLS_1_2 ; TLS_1_1 ; TLS_1_0 ] ;
  (* ordered list (regarding preference) *)
  hashes = Ciphersuite.([ SHA512 ; SHA384 ; SHA256 ; SHA ; MD5 ]) ;
  (* signatures = [ Packet.RSA ] *)
  (* whether or not to rekey *)
  rekeying = true ;
  validator = None ;
  peer_name = None ;
  own_certificate = None ;
}

let max_protocol_version config = List.hd config.protocol_versions
let min_protocol_version config = Utils.last config.protocol_versions

(* find highest version between v and supported versions *)
let supported_protocol_version config v =
  (* implicitly assumes that sups is decreasing ordered and without any holes *)
  let max = max_protocol_version config in
  let min = min_protocol_version config in
  match v >= max, v >= min with
    | true, _    -> Some max
    | _   , true -> Some v
    | _   , _    -> None

module Or_alert =
  Control.Or_error_make (struct type err = Packet.alert_type end)
open Or_alert

let fail_false v err =
  match v with
  | true ->  return ()
  | false -> fail err

let fail_neq cs1 cs2 err =
  fail_false (Utils.Cs.equal cs1 cs2) err

type iv_mode =       (* IV style *)
  | Iv of Cstruct.t  (* traditional CBC *)
  | Random_iv        (* tls 1.1 style *)

type cipher_st =
  | Stream : 'k Crypto.stream_cipher * 'k -> cipher_st
  | CBC    : 'k Crypto.cbc_cipher * 'k * iv_mode -> cipher_st
(*   | GCM : ... *)

type crypto_context = {
  sequence  : int64 ;
  cipher_st : cipher_st ;
  mac       : Crypto.hash_fn * Cstruct.t
}

type crypto_state = crypto_context option

type hs_log = Cstruct.t list
type master_secret = Cstruct.t

type peer_cert = Certificate.certificate

type dh_received = DH.group * Cstruct.t
type dh_sent = DH.group * DH.secret

type handshake_params = {
  server_random  : Cstruct.t ;
  client_random  : Cstruct.t ;
  client_version : tls_version ;
  cipher         : Ciphersuite.ciphersuite
}

type record = Packet.content_type * Cstruct.t

type server_handshake_state =
  | ServerInitial
  | ServerHelloDoneSent_RSA of handshake_params * hs_log
  | ServerHelloDoneSent_DHE_RSA of handshake_params * dh_sent * hs_log
  | ClientKeyExchangeReceived of crypto_context * crypto_context * master_secret * hs_log
  | ClientChangeCipherSpecReceived of master_secret * hs_log
  | ServerEstablished

type client_handshake_state =
  | ClientInitial
  | ClientHelloSent of handshake_params * hs_log
  | ServerHelloReceived of handshake_params * hs_log
  | ServerCertificateReceived_RSA of handshake_params * peer_cert * hs_log
  | ServerCertificateReceived_DHE_RSA of handshake_params * peer_cert * hs_log
  | ServerKeyExchangeReceived_DHE_RSA of handshake_params * dh_received * hs_log
  | ClientFinishedSent of crypto_context * Cstruct.t * master_secret * hs_log
  | ServerChangeCipherSpecReceived of Cstruct.t * master_secret * hs_log
  | ClientEstablished

type handshake_state =
  | Client of client_handshake_state
  | Server of server_handshake_state

type rekeying_params = Cstruct.t * Cstruct.t

type tls_internal_state = {
  version   : tls_version ;
  machina   : handshake_state ;
  config    : config ;
  rekeying  : rekeying_params option
}

(* this is the externally-visible state somebody will keep track of for us. *)
type state = {
  handshake : tls_internal_state ;
  decryptor : crypto_state ;
  encryptor : crypto_state ;
  fragment  : Cstruct.t ;
}

type role = [ `Server | `Client ]

let new_state config role =
  let handshake_state = match role with
    | `Client -> Client ClientInitial
    | `Server -> Server ServerInitial (* we should check that a own_cert is Some _ in config! *)
  in
  let handshake = {
    version   = max_protocol_version config ;
    rekeying  = None ;
    machina   = handshake_state ;
    config    = config
  }
  in
  {
    handshake = handshake ;
    decryptor = None ;
    encryptor = None ;
    fragment  = Cstruct.create 0
  }

let assemble_records : tls_version -> record list -> Cstruct.t =
  fun version ->
    o Utils.Cs.appends @@ List.map @@ Writer.assemble_hdr version

type rec_resp = [
  | `Change_enc of crypto_state
  | `Record     of record
]
type dec_resp = [ `Change_dec of crypto_state | `Pass ]

let divide_keyblock version key mac iv buf =
  let open Cstruct in
  let c_mac, rt0 = split buf mac in
  let s_mac, rt1 = split rt0 mac in
  let c_key, rt2 = split rt1 key in
  let s_key, rt3 = split rt2 key in
  let c_iv , s_iv = match version with
    | TLS_1_0           -> split rt3 iv
    | TLS_1_1 | TLS_1_2 -> (create 0, create 0)
  in
  (c_mac, s_mac, c_key, s_key, c_iv, s_iv)

let initialise_crypto_ctx version hp premaster =
  let open Ciphersuite in

  let master = Crypto.generate_master_secret version premaster
                (hp.client_random <+> hp.server_random) in

  let key_len, iv_len = ciphersuite_cipher_mac_length hp.cipher in

  let mac_algo = Crypto.Ciphers.get_hash (ciphersuite_mac hp.cipher) in
  let mac_len = Crypto.digest_size mac_algo in

  let kblen = match version with
    | TLS_1_0           -> 2 * key_len + 2 * mac_len + 2 * iv_len
    | TLS_1_1 | TLS_1_2 -> 2 * key_len + 2 * mac_len
  in
  let rand = hp.server_random <+> hp.client_random in
  let keyblock = Crypto.key_block version kblen master rand in

  let c_mac, s_mac, c_key, s_key, c_iv, s_iv =
    divide_keyblock version key_len mac_len iv_len keyblock in

  let enc_cipher = ciphersuite_cipher hp.cipher in

  let context cipher_k iv mac_k =
    let open Crypto.Ciphers in
    let cipher_st =
      match (get_cipher ~secret:cipher_k enc_cipher, version) with
      | (K_Stream (cip, st), _      ) -> Stream (cip, st)
      | (K_CBC    (cip, st), TLS_1_0) -> CBC (cip, st, Iv iv)
      | (K_CBC    (cip, st), TLS_1_1) -> CBC (cip, st, Random_iv)
      | (K_CBC    (cip, st), TLS_1_2) -> CBC (cip, st, Random_iv)
    and mac = (mac_algo, mac_k)
    and sequence = 0L in
    { cipher_st ; mac ; sequence }
  in

  let c_context = context c_key c_iv c_mac
  and s_context = context s_key s_iv s_mac in

  (c_context, s_context, master)


let can_send_appdata : state -> bool =
  fun s ->
    match s.handshake.machina with
    | Client ClientEstablished -> true
    | Server ServerEstablished -> true
    | _                        -> false

let alert typ =
  let buf = Writer.assemble_alert typ in
  (Packet.ALERT, buf)

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

let find_hostname : 'a hello -> string option =
  fun h ->
    let hexts = List.filter (function
                               | Hostname _ -> true
                               | _          -> false)
                             h.extensions
    in
    match hexts with
    | [Hostname name] -> name
    | _               -> None

let rec check_reneg expected = function
  | []                       -> fail Packet.NO_RENEGOTIATION
  | SecureRenegotiation x::_ -> fail_neq expected x Packet.NO_RENEGOTIATION
  | _::xs                    -> check_reneg expected xs

let handle_alert buf =
  match Reader.parse_alert buf with
  | Reader.Or_error.Ok al ->
     Printf.printf "ALERT: %s\n%!" (Printer.alert_to_string al);
     fail Packet.CLOSE_NOTIFY
  | Reader.Or_error.Error _ ->
     Printf.printf "unknown alert";
     Cstruct.hexdump buf;
     fail Packet.UNEXPECTED_MESSAGE

(* well-behaved pure encryptor *)
let encrypt (version : tls_version) (st : crypto_state) ty buf =
  match st with
  | None     -> (st, buf)
  | Some ctx ->
      let signature =
        let ver = pair_of_tls_version version in
        Crypto.mac ctx.mac ctx.sequence ty ver buf in

      let to_encrypt = buf <+> signature in

      let (st', enc) =
        match ctx.cipher_st with

        | Stream (m, key) ->
            let (message, key') =
              Crypto.encrypt_stream ~cipher:m ~key to_encrypt in
            (Stream (m, key'), message)

        | CBC (m, key, Iv iv) ->
            let (message, iv') =
              Crypto.encrypt_cbc ~cipher:m ~key ~iv to_encrypt in
            (CBC (m, key, Iv iv'), message)

        | CBC (m, key, Random_iv) ->
            let iv = Rng.generate (Crypto.cbc_block m) in
            let (message, _) =
              Crypto.encrypt_cbc ~cipher:m ~key ~iv to_encrypt in
            (CBC (m, key, Random_iv), iv <+> message)

      in
      let ctx' = { ctx with
                     sequence  = Int64.succ ctx.sequence ;
                     cipher_st = st' }
      in
      (Some ctx', enc)


let verify_mac { mac = (hash, _) as mac ; sequence } ty ver decrypted =
  let macstart = Cstruct.len decrypted - Crypto.digest_size hash in
  if macstart < 0 then fail Packet.BAD_RECORD_MAC else
    let (body, mmac) = Cstruct.split decrypted macstart in
    let cmac =
      let ver = pair_of_tls_version ver in
      Crypto.mac mac sequence ty ver body in
    fail_neq cmac mmac Packet.BAD_RECORD_MAC >>= fun () -> return body


let decrypt (version : tls_version) (st : crypto_state) ty buf =

  let verify ctx (st', dec) =
    verify_mac ctx ty version dec >>= fun body -> return (st', body)

  (* hmac is computed in this failure branch from the encrypted data, in the
     successful branch it is decrypted - padding (which is smaller equal than
     encrypted data) *)
  (* This comment is borrowed from miTLS, but applies here as well: *)
  (* We implement standard mitigation for padding oracles. Still, we note a
     small timing leak here: The time to verify the mac is linear in the
     plaintext length. *)
  (* defense against http://lasecwww.epfl.ch/memo/memo_ssl.shtml 1) in
     https://www.openssl.org/~bodo/tls-cbc.txt *)
  and mask_decrypt_failure ctx =
    verify_mac ctx ty version buf >>= fun _ -> fail Packet.BAD_RECORD_MAC
  in

  let dec ctx =
    match ctx.cipher_st with

    | Stream (m, key) ->
        let (message, key') = Crypto.decrypt_stream ~cipher:m ~key buf in
        verify ctx (Stream (m, key'), message)

    | CBC (m, key, Iv iv) ->
      ( match Crypto.decrypt_cbc ~cipher:m ~key ~iv buf with
        | None            -> mask_decrypt_failure ctx
        | Some (dec, iv') ->
            let st' = CBC (m, key, Iv iv') in
            verify ctx (st', dec) )

    | CBC (m, key, Random_iv) ->
        if Cstruct.len buf < Crypto.cbc_block m then
          fail Packet.BAD_RECORD_MAC
        else
          let (iv, buf) = Cstruct.split buf (Crypto.cbc_block m) in
          match Crypto.decrypt_cbc ~cipher:m ~key ~iv buf with
            | None          -> mask_decrypt_failure ctx
            | Some (dec, _) ->
                let st' = CBC (m, key, Random_iv) in
                verify ctx (st', dec)

  in
  match st with
  | None     -> return (st, buf)
  | Some ctx ->
      dec ctx >>= fun (st', msg) ->
      let ctx' = { ctx with
                     sequence  = Int64.succ ctx.sequence ;
                     cipher_st = st' }
      in
      return (Some ctx', msg)


let send_records (st : state) records =
  let version = st.handshake.version in
  let encryptor, encs = List.fold_left
    (fun (est, encs) (ty, cs)  ->
       let encryptor, enc = encrypt version est ty cs in
       (encryptor, encs @ [(ty, enc)]))
    (st.encryptor, [])
    records
  in
  let data = assemble_records version encs in
  ({ st with encryptor }, data)

let send_application_data (st : state) css =
  match can_send_appdata st with
  | true ->
     let datas = match st.encryptor with
       (* Mitigate implicit IV in CBC mode: prepend empty fragment *)
       | Some { cipher_st = CBC (_, _, Iv _) } -> Cstruct.create 0 :: css
       | _                                     -> css
     in
     let ty = Packet.APPLICATION_DATA in
     let data = List.map (fun cs -> (ty, cs)) datas in
     Some (send_records st data)
  | false -> None
