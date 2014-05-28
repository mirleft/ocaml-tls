open Core
open Nocrypto

module Or_alert =
  Control.Or_error_make (struct type err = Packet.alert_type end)
open Or_alert

let fail_false v err =
  match v with
  | true ->  return ()
  | false -> fail err

let fail_neq cs1 cs2 err =
  fail_false (Utils.Cs.equal cs1 cs2) err

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
  let (<+>) = Utils.Cs.(<+>) in

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
  config    : Config.config ;
  rekeying  : rekeying_params option
}

type crypto_state = crypto_context option

(* return type of handshake handlers *)
type record = Packet.content_type * Cstruct.t
type rec_resp = [
  | `Change_enc of crypto_state
  | `Record     of record
]
type dec_resp = [ `Change_dec of crypto_state | `Pass ]
type handshake_return = tls_internal_state * rec_resp list * dec_resp


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

