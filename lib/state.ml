(* Defines all high-level datatypes for the TLS library. It is opaque to clients
 of this library, and only used from within the library. *)

open Sexplib
open Sexplib.Conv

open Core
open Nocrypto

(* initialisation vector style, depending on TLS version *)
type iv_mode =
  | Iv of Cstruct_s.t  (* traditional CBC (reusing last cipherblock) *)
  | Random_iv          (* TLS 1.1 and higher explicit IV (we use random) *)
  with sexp

(* state of a symmetric cipher *)
type cipher_st =
  | Stream : 'k Crypto.stream_cipher * 'k -> cipher_st (* stream cipher state *)
  | CBC    : 'k Crypto.cbc_cipher * 'k * iv_mode -> cipher_st (* block cipher state *)
(*   | GCM : ... *)

(* context of a TLS connection (both in and out has each one of these) *)
type crypto_context = {
  sequence  : int64 ; (* sequence number *)
  cipher_st : cipher_st ; (* cipher state *)
  mac       : Crypto.hash_fn * Cstruct.t (* hmac state *)
}

(* Sexplib stubs -- rethink how to play with crypto. *)

let sexp_of_cipher_st = function
  | Stream _        -> Sexp.(Atom "<stream-state>")
  | CBC (_, _, ivm) -> Sexp.(List [Atom "<cbc-state>"; sexp_of_iv_mode ivm])

let crypto_context_of_sexp _ = failwith "can't parse crypto context from sexp"
and sexp_of_crypto_context cc =
  Sexp_ext.record [
    "sequence" , sexp_of_int64 cc.sequence ;
    "cipher_st", sexp_of_cipher_st cc.cipher_st ;
    "mac"      , Cstruct_s.sexp_of_t (snd cc.mac)
  ]

(* *** *)

(* the raw handshake log we need to carry around *)
type hs_log = Cstruct_s.t list with sexp
(* the master secret of a TLS connection *)
type master_secret = Cstruct_s.t with sexp
(* diffie hellman group and secret *)
type dh_sent = DH.group * DH.secret with sexp

(* a collection of client and server verify bytes for renegotiation *)
type reneg_params = Cstruct_s.t * Cstruct_s.t
  with sexp

type session_data = {
  server_random    : Cstruct_s.t ; (* 32 bytes random from the server hello *)
  client_random    : Cstruct_s.t ; (* 32 bytes random from the client hello *)
  client_version   : tls_any_version ; (* version in client hello (needed in RSA client key exchange) *)
  ciphersuite      : Ciphersuite.ciphersuite ;
  peer_certificate : Certificate.certificate list ;
  own_certificate  : Certificate.certificate list ;
  own_private_key  : Nocrypto.RSA.priv option ;
  master_secret    : master_secret ;
  renegotiation    : reneg_params ; (* renegotiation data *)
  own_name         : string option ;
  previous_session : session_data option ;
} with sexp

(* state machine of the server *)
type server_handshake_state =
  | AwaitClientHello (* initial state *)
  | AwaitClientKeyExchange_RSA of session_data * hs_log (* server hello done is sent, and RSA key exchange used, waiting for a client key exchange message *)
  | AwaitClientKeyExchange_DHE_RSA of session_data * dh_sent * hs_log (* server hello done is sent, and DHE_RSA key exchange used, waiting for client key exchange *)
  | AwaitClientChangeCipherSpec of session_data * crypto_context * crypto_context * hs_log (* client key exchange received, next should be change cipher spec *)
  | AwaitClientFinished of session_data * hs_log (* change cipher spec received, next should be the finished including a hmac over all handshake packets *)
  | Established (* handshake successfully completed *)
  with sexp

(* state machine of the client *)
type client_handshake_state =
  | ClientInitial (* initial state *)
  | AwaitServerHello of client_hello * hs_log (* client hello is sent, handshake_params are half-filled *)
  | AwaitServerHelloRenegotiate of session_data * client_hello * hs_log (* client hello is sent, handshake_params are half-filled *)
  | AwaitCertificate_RSA of session_data * hs_log (* certificate expected with RSA key exchange *)
  | AwaitCertificate_DHE_RSA of session_data * hs_log (* certificate expected with DHE_RSA key exchange *)
  | AwaitServerKeyExchange_DHE_RSA of session_data * hs_log (* server key exchange expected with DHE_RSA *)
  | AwaitServerHelloDone of session_data * Cstruct_s.t * Cstruct_s.t * hs_log (* server hello done expected, client key exchange and premastersecret are ready *)
  | AwaitServerChangeCipherSpec of session_data * crypto_context * Cstruct_s.t * hs_log (* change cipher spec expected *)
  | AwaitServerFinished of session_data * Cstruct_s.t * hs_log (* finished expected with a hmac over all handshake packets *)
  | Established (* handshake successfully completed *)
  with sexp

type handshake_machina_state =
  | Client of client_handshake_state
  | Server of server_handshake_state
  with sexp

(* state during a handshake, used in the handlers *)
type handshake_state = {
  session          : session_data option ;
  protocol_version : tls_version ;
  machina          : handshake_machina_state ; (* state machine state *)
  config           : Config.config ; (* given config *)
  hs_fragment      : Cstruct_s.t (* handshake messages can be fragmented, leftover from before *)
} with sexp

(* connection state: initially None, after handshake a crypto context *)
type crypto_state = crypto_context option
  with sexp

(* record consisting of a content type and a byte vector *)
type record = Packet.content_type * Cstruct_s.t with sexp

(* response returned by a handler *)
type rec_resp = [
  | `Change_enc of crypto_state (* either instruction to change the encryptor to the given one *)
  | `Record     of record (* or a record which should be sent out *)
]

(* response for the decryption part *)
type dec_resp = [
  | `Change_dec of crypto_state (* either change the decryptor to the given one *)
  | `Pass (* do not change anything *)
]

(* return type of handshake handlers *)
type handshake_return = handshake_state * rec_resp list

(* return type of change cipher spec handlers *)
type ccs_return = handshake_state * rec_resp list * dec_resp

(* Top level state, encapsulating the entire session. *)
type state = {
  handshake : handshake_state ; (* the current handshake state *)
  decryptor : crypto_state ; (* the current decryption state *)
  encryptor : crypto_state ; (* the current encryption state *)
  fragment  : Cstruct_s.t ; (* the leftover fragment from TCP fragmentation *)
} with sexp

