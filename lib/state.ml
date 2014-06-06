open Sexplib
open Sexplib.Conv

open Core
open Nocrypto


type iv_mode =         (* IV style *)
  | Iv of Cstruct_s.t  (* traditional CBC *)
  | Random_iv          (* tls 1.1 style *)
  with sexp

type cipher_st =
  | Stream : 'k Crypto.stream_cipher * 'k -> cipher_st
  | CBC    : 'k Crypto.cbc_cipher * 'k * iv_mode -> cipher_st
(*   | GCM : ... *)

type crypto_context = {
  sequence  : int64 ;
  cipher_st : cipher_st ;
  mac       : Crypto.hash_fn * Cstruct.t
}

(* Sexplib stubs -- rethink how to play with crypto. *)

let crypto_context_of_sexp _ = failwith "can't parse crypto context from sexp"
and sexp_of_crypto_context cc =
  Sexp.(List [Atom "sequence"; sexp_of_int64 cc.sequence])

module DH = struct
  include DH
  let group_of_sexp _ = failwith "can't parse dh_group from sexp"
  and sexp_of_group _ = Sexp.Atom "-SOME-DH-GROUP-"
  let secret_of_sexp _ = failwith "can't parse dh_secret from sexp"
  and sexp_of_secret _ = Sexp.Atom "-A-DH-SECRET-"
end

(* *** *)


type hs_log = Cstruct_s.t list
  with sexp
type master_secret = Cstruct_s.t
  with sexp

type dh_received = DH.group * Cstruct_s.t
  with sexp
type dh_sent = DH.group * DH.secret
  with sexp


type handshake_params = {
  server_random  : Cstruct_s.t ;
  client_random  : Cstruct_s.t ;
  client_version : tls_version ;
  cipher         : Ciphersuite.ciphersuite
} with sexp

type server_handshake_state =
  | ServerInitial
  | ServerHelloDoneSent_RSA of handshake_params * hs_log
  | ServerHelloDoneSent_DHE_RSA of handshake_params * dh_sent * hs_log
  | ClientKeyExchangeReceived of crypto_context * crypto_context * master_secret * hs_log
  | ClientChangeCipherSpecReceived of master_secret * hs_log
  | ServerEstablished
  with sexp

type client_handshake_state =
  | ClientInitial
  | ClientHelloSent of client_hello * handshake_params * hs_log
  | ServerHelloReceived of handshake_params * hs_log
  | ServerCertificateReceived_RSA of handshake_params * Certificate.certificate * hs_log
  | ServerCertificateReceived_DHE_RSA of handshake_params * Certificate.certificate * hs_log
  | ServerKeyExchangeReceived_DHE_RSA of handshake_params * dh_received * hs_log
  | ClientFinishedSent of crypto_context * Cstruct_s.t * master_secret * hs_log
  | ServerChangeCipherSpecReceived of Cstruct_s.t * master_secret * hs_log
  | ClientEstablished
  with sexp

type handshake_machina_state =
  | Client of client_handshake_state
  | Server of server_handshake_state
  with sexp

type rekeying_params = Cstruct_s.t * Cstruct_s.t
  with sexp

type handshake_state = {
  version      : tls_version ;
  machina      : handshake_machina_state ;
  config       : Config.config ;
  rekeying     : rekeying_params option ;
  hs_fragment  : Cstruct_s.t
} with sexp

type crypto_state = crypto_context option
  with sexp

(* return type of handlers *)
type record = Packet.content_type * Cstruct_s.t
  with sexp
type rec_resp = [
  | `Change_enc of crypto_state
  | `Record     of record
]
type dec_resp = [ `Change_dec of crypto_state | `Pass ]
type handshake_return = handshake_state * rec_resp list
type ccs_return = handshake_state * rec_resp list * dec_resp

(* Top level state, encapsulating the entire session. *)
type state = {
  handshake : handshake_state ;
  decryptor : crypto_state ;
  encryptor : crypto_state ;
  fragment  : Cstruct_s.t ;
} with sexp
