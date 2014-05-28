open Core
open Nocrypto

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


module Or_alert =
  Control.Or_error_make (struct type err = Packet.alert_type end)
open Or_alert

let fail_false v err =
  match v with
  | true ->  return ()
  | false -> fail err

let fail_neq cs1 cs2 err =
  fail_false (Utils.Cs.equal cs1 cs2) err

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

