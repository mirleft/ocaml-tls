(* Defines all high-level datatypes for the TLS library. It is opaque to clients
 of this library, and only used from within the library. *)

open Sexplib
open Sexplib.Conv

open Core
open Nocrypto

type hmac_key = Cstruct.t

type 'k stream_state = {
  cipher         : (module Cipher_stream.T    with type key = 'k) ;
  cipher_secret  : 'k ;
  hmac           : Hash.hash ;
  hmac_secret    : hmac_key
}

(* initialisation vector style, depending on TLS version *)
type iv_mode =
  | Iv of Cstruct_s.t  (* traditional CBC (reusing last cipherblock) *)
  | Random_iv          (* TLS 1.1 and higher explicit IV (we use random) *)
  with sexp
type 'k cbc_cipher    = (module Cipher_block.T.CBC with type key = 'k)
type 'k cbc_state = {
  cipher         : 'k cbc_cipher ;
  cipher_secret  : 'k ;
  iv_mode        : iv_mode ;
  hmac           : Hash.hash ;
  hmac_secret    : hmac_key
}

type nonce = Cstruct.t
type 'k ccm_state = {
  cipher         : (module Cipher_block.T.CCM with type key = 'k) ;
  cipher_secret  : 'k ;
  nonce          : nonce
}

(* state of a symmetric cipher *)
type cipher_st =
  | Stream : 'k stream_state -> cipher_st
  | CBC    : 'k cbc_state -> cipher_st
  | CCM    : 'k ccm_state -> cipher_st

(* context of a TLS connection (both in and out has each one of these) *)
type crypto_context = {
  sequence  : int64 ; (* sequence number *)
  cipher_st : cipher_st ; (* cipher state *)
}

(* Sexplib stubs -- rethink how to play with crypto. *)

let sexp_of_cipher_st = function
  | Stream _ -> Sexp.(Atom "<stream-state>")
  | CBC _    -> Sexp.(Atom "<cbc-state>")
  | CCM _    -> Sexp.(Atom "<ccm-state>")

let crypto_context_of_sexp _ = failwith "can't parse crypto context from sexp"
and sexp_of_crypto_context cc =
  Sexp_ext.record [
    "sequence" , sexp_of_int64 cc.sequence ;
    "cipher_st", sexp_of_cipher_st cc.cipher_st
  ]

(* *** *)

(* the raw handshake log we need to carry around *)
type hs_log = Cstruct_s.t list with sexp
(* the master secret of a TLS connection *)
type master_secret = Cstruct_s.t with sexp
(* diffie hellman group and secret *)
type dh_sent = Dh.group * Dh.secret with sexp

(* a collection of client and server verify bytes for renegotiation *)
type reneg_params = Cstruct_s.t * Cstruct_s.t
  with sexp

type session_data = {
  server_random    : Cstruct_s.t ; (* 32 bytes random from the server hello *)
  client_random    : Cstruct_s.t ; (* 32 bytes random from the client hello *)
  client_version   : tls_any_version ; (* version in client hello (needed in RSA client key exchange) *)
  ciphersuite      : Ciphersuite.ciphersuite ;
  peer_certificate : X509.Certificate.certificate list ;
  trust_anchor     : X509.Certificate.certificate option ;
  own_certificate  : X509.Certificate.certificate list ;
  own_private_key  : Nocrypto.Rsa.priv option ;
  master_secret    : master_secret ;
  renegotiation    : reneg_params ; (* renegotiation data *)
  own_name         : string option ;
  client_auth      : bool ;
} with sexp

(* state machine of the server *)
type server_handshake_state =
  | AwaitClientHello (* initial state *)
  | AwaitClientHelloRenegotiate
  | AwaitClientCertificate_RSA of session_data * hs_log
  | AwaitClientCertificate_DHE_RSA of session_data * dh_sent * hs_log
  | AwaitClientKeyExchange_RSA of session_data * hs_log (* server hello done is sent, and RSA key exchange used, waiting for a client key exchange message *)
  | AwaitClientKeyExchange_DHE_RSA of session_data * dh_sent * hs_log (* server hello done is sent, and DHE_RSA key exchange used, waiting for client key exchange *)
  | AwaitClientCertificateVerify of session_data * crypto_context * crypto_context * hs_log
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
  | AwaitCertificateRequestOrServerHelloDone of session_data * Cstruct_s.t * Cstruct_s.t * hs_log (* server hello done expected, client key exchange and premastersecret are ready *)
  | AwaitServerHelloDone of session_data * (Hash.hash * Packet.signature_algorithm_type) list option * Cstruct_s.t * Cstruct_s.t * hs_log (* server hello done expected, client key exchange and premastersecret are ready *)
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
  session          : session_data list ;
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

type error = [
  | `AuthenticationFailure of X509.Certificate.certificate_failure
  | `NoConfiguredCiphersuite of Ciphersuite.ciphersuite list
  | `NoConfiguredVersion of tls_version
  | `NoConfiguredHash of Hash.hash list
  | `NoSecureRenegotiation
  | `NoMatchingCertificateFound of string
  | `NoCertificateConfigured
  | `CouldntSelectCertificate
] with sexp

type fatal = [
  | `NoCiphersuite of Packet.any_ciphersuite list
  | `NoVersion of tls_any_version
  | `ReaderError of Reader.error
  | `NoCertificateReceived
  | `NotRSACertificate
  | `NotRSASignature
  | `KeyTooSmall
  | `RSASignatureMismatch
  | `RSASignatureVerificationFailed
  | `HashAlgorithmMismatch
  | `BadCertificateChain
  | `MACMismatch
  | `MACUnderflow
  | `RecordOverflow of int
  | `UnknownRecordVersion of int * int
  | `UnknownContentType of int
  | `CannotHandleApplicationDataYet
  | `NoHeartbeat
  | `BadRecordVersion of tls_any_version
  | `BadFinished
  | `HandshakeFragmentsNotEmpty
  | `InvalidDH
  | `MixedCiphersuites
  | `InvalidRenegotiation
  | `InvalidClientHello
  | `InvalidServerHello
  | `InvalidRenegotiationVersion of tls_version
  | `InappropriateFallback
  | `UnexpectedCCS
  | `UnexpectedHandshake of tls_handshake
  | `InvalidCertificateUsage
  | `InvalidCertificateExtendedUsage
  | `InvalidSession
] with sexp

type failure = [
  | `Error of error
  | `Fatal of fatal
] with sexp

(* Monadic control-flow core. *)
include Control.Or_error_make (struct type err = failure end)
