(* Defines all high-level datatypes for the TLS library. It is opaque to clients
 of this library, and only used from within the library. *)

open Core
open Mirage_crypto

type hmac_key = Cstruct.t

(* initialisation vector style, depending on TLS version *)
type iv_mode =
  | Iv of Cstruct.t  (* traditional CBC (reusing last cipherblock) *)
  | Random_iv        (* TLS 1.1 and higher explicit IV (we use random) *)

type 'k cbc_cipher    = (module Cipher_block.S.CBC with type key = 'k)
type 'k cbc_state = {
  cipher         : 'k cbc_cipher ;
  cipher_secret  : 'k ;
  iv_mode        : iv_mode ;
  hmac           : Hash.hash ;
  hmac_secret    : hmac_key
}

type nonce = Cstruct.t

type 'k aead_cipher = (module AEAD with type key = 'k)
type 'k aead_state = {
  cipher         : 'k aead_cipher ;
  cipher_secret  : 'k ;
  nonce          : nonce ;
  explicit_nonce : bool ; (* RFC 7905: no explicit nonce, instead TLS 1.3 construction is adapted *)

}

(* state of a symmetric cipher *)
type cipher_st =
  | CBC    : 'k cbc_state -> cipher_st
  | AEAD   : 'k aead_state -> cipher_st

(* context of a TLS connection (both in and out has each one of these) *)
type crypto_context = {
  sequence  : int64 ; (* sequence number *)
  cipher_st : cipher_st ; (* cipher state *)
}
(* the raw handshake log we need to carry around *)
type hs_log = Cstruct.t list

type dh_secret = [
  | `Finite_field of Mirage_crypto_pk.Dh.secret
  | `P256 of Mirage_crypto_ec.P256.Dh.secret
  | `P384 of Mirage_crypto_ec.P384.Dh.secret
  | `P521 of Mirage_crypto_ec.P521.Dh.secret
  | `X25519 of Mirage_crypto_ec.X25519.secret
]

(* a collection of client and server verify bytes for renegotiation *)
type reneg_params = Cstruct.t * Cstruct.t

type common_session_data = {
  server_random          : Cstruct.t ; (* 32 bytes random from the server hello *)
  client_random          : Cstruct.t ; (* 32 bytes random from the client hello *)
  peer_certificate_chain : X509.Certificate.t list ;
  peer_certificate       : X509.Certificate.t option ;
  trust_anchor           : X509.Certificate.t option ;
  received_certificates  : X509.Certificate.t list ;
  own_certificate        : X509.Certificate.t list ;
  own_private_key        : X509.Private_key.t option ;
  own_name               : [`host] Domain_name.t option ;
  client_auth            : bool ;
  master_secret          : master_secret ;
  alpn_protocol          : string option ; (* selected alpn protocol after handshake *)
}

type session_data = {
  common_session_data    : common_session_data ;
  client_version         : tls_any_version ; (* version in client hello (needed in RSA client key exchange) *)
  ciphersuite            : Ciphersuite.ciphersuite ;
  group                  : group option ;
  renegotiation          : reneg_params ; (* renegotiation data *)
  session_id             : Cstruct.t ;
  extended_ms            : bool ;
}

(* state machine of the server *)
type server_handshake_state =
  | AwaitClientHello (* initial state *)
  | AwaitClientHelloRenegotiate
  | AwaitClientCertificate_RSA of session_data * hs_log
  | AwaitClientCertificate_DHE of session_data * dh_secret * hs_log
  | AwaitClientKeyExchange_RSA of session_data * hs_log (* server hello done is sent, and RSA key exchange used, waiting for a client key exchange message *)
  | AwaitClientKeyExchange_DHE of session_data * dh_secret * hs_log (* server hello done is sent, and DHE_RSA key exchange used, waiting for client key exchange *)
  | AwaitClientCertificateVerify of session_data * crypto_context * crypto_context * hs_log
  | AwaitClientChangeCipherSpec of session_data * crypto_context * crypto_context * hs_log (* client key exchange received, next should be change cipher spec *)
  | AwaitClientChangeCipherSpecResume of session_data * crypto_context * Cstruct.t * hs_log (* resumption: next should be change cipher spec *)
  | AwaitClientFinished of session_data * hs_log (* change cipher spec received, next should be the finished including a hmac over all handshake packets *)
  | AwaitClientFinishedResume of session_data * Cstruct.t * hs_log (* change cipher spec received, next should be the finished including a hmac over all handshake packets *)
  | Established (* handshake successfully completed *)

(* state machine of the client *)
type client_handshake_state =
  | ClientInitial (* initial state *)
  | AwaitServerHello of client_hello * (group * dh_secret) list * hs_log (* client hello is sent, handshake_params are half-filled *)
  | AwaitServerHelloRenegotiate of session_data * client_hello * hs_log (* client hello is sent, handshake_params are half-filled *)
  | AwaitCertificate_RSA of session_data * hs_log (* certificate expected with RSA key exchange *)
  | AwaitCertificate_DHE of session_data * hs_log (* certificate expected with DHE key exchange *)
  | AwaitServerKeyExchange_DHE of session_data * hs_log (* server key exchange expected with DHE *)
  | AwaitCertificateRequestOrServerHelloDone of session_data * Cstruct.t * Cstruct.t * hs_log (* server hello done expected, client key exchange and premastersecret are ready *)
  | AwaitServerHelloDone of session_data * signature_algorithm list option * Cstruct.t * Cstruct.t * hs_log (* server hello done expected, client key exchange and premastersecret are ready *)
  | AwaitServerChangeCipherSpec of session_data * crypto_context * Cstruct.t * hs_log (* change cipher spec expected *)
  | AwaitServerChangeCipherSpecResume of session_data * crypto_context * crypto_context * hs_log (* change cipher spec expected *)
  | AwaitServerFinished of session_data * Cstruct.t * hs_log (* finished expected with a hmac over all handshake packets *)
  | AwaitServerFinishedResume of session_data * hs_log (* finished expected with a hmac over all handshake packets *)
  | Established (* handshake successfully completed *)

type kdf = {
  secret : Cstruct.t ;
  cipher : Ciphersuite.ciphersuite13 ;
  hash : Mirage_crypto.Hash.hash ;
}

(* TODO needs log of CH..CF for post-handshake auth *)
(* TODO drop master_secret!? *)
type session_data13 = {
  common_session_data13  : common_session_data ;
  ciphersuite13          : Ciphersuite.ciphersuite13 ;
  master_secret          : kdf ;
  resumption_secret      : Cstruct.t ;
  state                  : epoch_state ;
  resumed                : bool ;
  client_app_secret      : Cstruct.t ;
  server_app_secret      : Cstruct.t ;
}

type client13_handshake_state =
  | AwaitServerHello13 of client_hello * (group * dh_secret) list * Cstruct.t (* this is for CH1 ~> HRR ~> CH2 <~ WAIT SH *)
  | AwaitServerEncryptedExtensions13 of session_data13 * Cstruct.t * Cstruct.t * Cstruct.t
  | AwaitServerCertificateRequestOrCertificate13 of session_data13 * Cstruct.t * Cstruct.t * Cstruct.t
  | AwaitServerCertificate13 of session_data13 * Cstruct.t * Cstruct.t * signature_algorithm list option * Cstruct.t
  | AwaitServerCertificateVerify13 of session_data13 * Cstruct.t * Cstruct.t * signature_algorithm list option * Cstruct.t
  | AwaitServerFinished13 of session_data13 * Cstruct.t * Cstruct.t * signature_algorithm list option * Cstruct.t
  | Established13

type server13_handshake_state =
  | AwaitClientHelloHRR13 (* if we sent out HRR (also to-be-used for tls13-only) *)
  | AwaitClientCertificate13 of session_data13 * Cstruct.t * crypto_context * session_ticket option * Cstruct.t
  | AwaitClientCertificateVerify13 of session_data13 * Cstruct.t * crypto_context * session_ticket option * Cstruct.t
  | AwaitClientFinished13 of Cstruct.t * crypto_context * session_ticket option * Cstruct.t
  | AwaitEndOfEarlyData13 of Cstruct.t * crypto_context * crypto_context * session_ticket option * Cstruct.t
  | Established13

type handshake_machina_state =
  | Client of client_handshake_state
  | Server of server_handshake_state
  | Client13 of client13_handshake_state
  | Server13 of server13_handshake_state

(* state during a handshake, used in the handlers *)
type handshake_state = {
  session          : [ `TLS of session_data | `TLS13 of session_data13 ] list ;
  protocol_version : tls_version ;
  early_data_left  : int32 ;
  machina          : handshake_machina_state ; (* state machine state *)
  config           : Config.config ; (* given config *)
  hs_fragment      : Cstruct.t ; (* handshake messages can be fragmented, leftover from before *)
}

(* connection state: initially None, after handshake a crypto context *)
type crypto_state = crypto_context option

(* record consisting of a content type and a byte vector *)
type record = Packet.content_type * Cstruct.t

(* response returned by a handler *)
type rec_resp = [
  | `Change_enc of crypto_context (* either instruction to change the encryptor to the given one *)
  | `Change_dec of crypto_context (* either change the decryptor to the given one *)
  | `Record     of record (* or a record which should be sent out *)
]

(* return type of handshake handlers *)
type handshake_return = handshake_state * rec_resp list

(* Top level state, encapsulating the entire session. *)
type state = {
  handshake : handshake_state ; (* the current handshake state *)
  decryptor : crypto_state ; (* the current decryption state *)
  encryptor : crypto_state ; (* the current encryption state *)
  fragment  : Cstruct.t ; (* the leftover fragment from TCP fragmentation *)
}

type error = [
  | `AuthenticationFailure of X509.Validation.validation_error
  | `NoConfiguredCiphersuite of Ciphersuite.ciphersuite list
  | `NoConfiguredVersions of tls_version list
  | `NoConfiguredSignatureAlgorithm of signature_algorithm list
  | `NoMatchingCertificateFound of string
  | `NoCertificateConfigured
  | `CouldntSelectCertificate
]

let pp_error ppf = function
  | `AuthenticationFailure v ->
    Fmt.pf ppf "authentication failure: %a" X509.Validation.pp_validation_error v
  | `NoConfiguredCiphersuite cs ->
    Fmt.pf ppf "no configured ciphersuite: %a"
      Fmt.(list ~sep:(any ", ") Ciphersuite.pp_ciphersuite) cs
  | `NoConfiguredVersions vs ->
    Fmt.pf ppf "no configured version: %a"
      Fmt.(list ~sep:(any ", ") pp_tls_version) vs
  | `NoConfiguredSignatureAlgorithm sas ->
    Fmt.pf ppf "no configure signature algorithm: %a"
      Fmt.(list ~sep:(any ", ") pp_signature_algorithm) sas
  | `NoMatchingCertificateFound host ->
    Fmt.pf ppf "no matching certificate found for %s" host
  | `NoCertificateConfigured -> Fmt.string ppf "no certificate configured"
  | `CouldntSelectCertificate -> Fmt.string ppf "couldn't select certificate"

type client_hello_errors = [
  | `EmptyCiphersuites
  | `NotSetCiphersuites of Packet.any_ciphersuite list
  | `NoSupportedCiphersuite of Packet.any_ciphersuite list
  | `NotSetExtension of client_extension list
  | `NoSignatureAlgorithmsExtension
  | `NoGoodSignatureAlgorithms of signature_algorithm list
  | `NoKeyShareExtension
  | `NoSupportedGroupExtension
  | `NotSetSupportedGroup of Packet.named_group list
  | `NotSetKeyShare of (Packet.named_group * Cstruct.t) list
  | `NotSubsetKeyShareSupportedGroup of Packet.named_group list * (Packet.named_group * Cstruct.t) list
  | `Has0rttAfterHRR
  | `NoCookie
]

let pp_client_hello_error ppf = function
  | `EmptyCiphersuites -> Fmt.string ppf "empty ciphersuites"
  | `NotSetCiphersuites cs ->
    Fmt.pf ppf "ciphersuites not a set: %a"
      Fmt.(list ~sep:(any ", ") Ciphersuite.pp_any_ciphersuite) cs
  | `NoSupportedCiphersuite cs ->
    Fmt.pf ppf "no supported ciphersuite %a"
      Fmt.(list ~sep:(any ", ") Ciphersuite.pp_any_ciphersuite) cs
  | `NotSetExtension _ -> Fmt.string ppf "extensions not a set"
  | `NoSignatureAlgorithmsExtension ->
    Fmt.string ppf "no signature algorithms extension"
  | `NoGoodSignatureAlgorithms sas ->
    Fmt.pf ppf "no good signature algorithm: %a"
      Fmt.(list ~sep:(any ", ") pp_signature_algorithm) sas
  | `NoKeyShareExtension -> Fmt.string ppf "no keyshare extension"
  | `NoSupportedGroupExtension ->
    Fmt.string ppf "no supported group extension"
  | `NotSetSupportedGroup groups ->
    Fmt.pf ppf "supported groups not a set: %a"
      Fmt.(list ~sep:(any ", ") int) (List.map Packet.named_group_to_int groups)
  | `NotSetKeyShare ks ->
    Fmt.pf ppf "key share not a set: %a"
      Fmt.(list ~sep:(any ", ") int)
      (List.map (fun (g, _) -> Packet.named_group_to_int g) ks)
  | `NotSubsetKeyShareSupportedGroup (ng, ks) ->
    Fmt.pf ppf "key share not a subset of supported groups: %a@ keyshare %a"
      Fmt.(list ~sep:(any ", ") int) (List.map Packet.named_group_to_int ng)
      Fmt.(list ~sep:(any ", ") int)
      (List.map (fun (g, _) -> Packet.named_group_to_int g) ks)
  | `Has0rttAfterHRR -> Fmt.string ppf "has 0RTT after HRR"
  | `NoCookie -> Fmt.string ppf "no cookie"

type fatal = [
  | `NoSecureRenegotiation
  | `NoSupportedGroup
  | `NoVersions of tls_any_version list
  | `ReaderError of Reader.error
  | `NoCertificateReceived
  | `NoCertificateVerifyReceived
  | `NotRSACertificate
  | `KeyTooSmall
  | `SignatureVerificationFailed of string
  | `SigningFailed of string
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
  | `InsufficientDH
  | `InvalidDH
  | `BadECDH of Mirage_crypto_ec.error
  | `InvalidRenegotiation
  | `InvalidClientHello of client_hello_errors
  | `InvalidServerHello
  | `InvalidRenegotiationVersion of tls_version
  | `InappropriateFallback
  | `UnexpectedCCS
  | `UnexpectedHandshake of tls_handshake
  | `InvalidCertificateUsage
  | `InvalidCertificateExtendedUsage
  | `InvalidSession
  | `NoApplicationProtocol
  | `HelloRetryRequest
  | `InvalidMessage
  | `Toomany0rttbytes
  | `MissingContentType
  | `Downgrade12
  | `Downgrade11
]

let pp_fatal ppf = function
  | `NoSecureRenegotiation -> Fmt.string ppf "no secure renegotiation"
  | `NoSupportedGroup -> Fmt.string ppf "no supported group"
  | `NoVersions vs ->
    Fmt.pf ppf "no versions %a" Fmt.(list ~sep:(any ", ") pp_tls_any_version) vs
  | `ReaderError re -> Fmt.pf ppf "reader error: %a" Reader.pp_error re
  | `NoCertificateReceived -> Fmt.string ppf "no certificate received"
  | `NoCertificateVerifyReceived ->
    Fmt.string ppf "no certificate verify received"
  | `NotRSACertificate -> Fmt.string ppf "not a RSA certificate"
  | `KeyTooSmall -> Fmt.string ppf "key too small"
  | `SignatureVerificationFailed msg ->
    Fmt.pf ppf "signature verification failed: %s" msg
  | `SigningFailed msg -> Fmt.pf ppf "signing failed: %s" msg
  | `BadCertificateChain -> Fmt.string ppf "bad certificate chain"
  | `MACMismatch -> Fmt.string ppf "MAC mismatch"
  | `MACUnderflow -> Fmt.string ppf "MAC underflow"
  | `RecordOverflow n -> Fmt.pf ppf "record overflow %u" n
  | `UnknownRecordVersion (m, n) ->
    Fmt.pf ppf "unknown record version %u.%u" m n
  | `UnknownContentType c -> Fmt.pf ppf "unknown content type %u" c
  | `CannotHandleApplicationDataYet ->
    Fmt.string ppf "cannot handle application data yet"
  | `NoHeartbeat -> Fmt.string ppf "no heartbeat"
  | `BadRecordVersion v ->
    Fmt.pf ppf "bad record version %a" pp_tls_any_version v
  | `BadFinished -> Fmt.string ppf "bad finished"
  | `HandshakeFragmentsNotEmpty ->
    Fmt.string ppf "handshake fragments not empty"
  | `InsufficientDH -> Fmt.string ppf "insufficient DH"
  | `InvalidDH -> Fmt.string ppf "invalid DH"
  | `BadECDH e -> Fmt.pf ppf "bad ECDH %a" Mirage_crypto_ec.pp_error e
  | `InvalidRenegotiation -> Fmt.string ppf "invalid renegotiation"
  | `InvalidClientHello ce ->
    Fmt.pf ppf "invalid client hello: %a" pp_client_hello_error ce
  | `InvalidServerHello -> Fmt.string ppf "invalid server hello"
  | `InvalidRenegotiationVersion v ->
    Fmt.pf ppf "invalid renegotiation version %a" pp_tls_version v
  | `InappropriateFallback -> Fmt.string ppf "inappropriate fallback"
  | `UnexpectedCCS -> Fmt.string ppf "unexpected change cipher spec"
  | `UnexpectedHandshake hs ->
    Fmt.pf ppf "unexpected handshake %a" pp_handshake hs
  | `InvalidCertificateUsage -> Fmt.string ppf "invalid certificate usage"
  | `InvalidCertificateExtendedUsage ->
    Fmt.string ppf "invalid certificate extended usage"
  | `InvalidSession -> Fmt.string ppf "invalid session"
  | `NoApplicationProtocol -> Fmt.string ppf "no application protocol"
  | `HelloRetryRequest -> Fmt.string ppf "hello retry request"
  | `InvalidMessage -> Fmt.string ppf "invalid message"
  | `Toomany0rttbytes -> Fmt.string ppf "too many 0RTT bytes"
  | `MissingContentType -> Fmt.string ppf "missing content type"
  | `Downgrade12 -> Fmt.string ppf "downgrade 1.2"
  | `Downgrade11 -> Fmt.string ppf "downgrade 1.1"

type failure = [
  | `Error of error
  | `Fatal of fatal
]

let pp_failure ppf = function
  | `Error e -> pp_error ppf e
  | `Fatal f -> pp_fatal ppf f

let common_data_to_epoch common is_server peer_name =
  let own_random, peer_random =
    if is_server then
      common.server_random, common.client_random
    else
      common.client_random, common.server_random
  in
  let epoch : epoch_data =
    { state                  = `Established ;
      protocol_version       = `TLS_1_0 ;
      ciphersuite            = `DHE_RSA_WITH_AES_256_CBC_SHA ;
      peer_random ;
      peer_certificate       = common.peer_certificate ;
      peer_certificate_chain = common.peer_certificate_chain ;
      peer_name ;
      trust_anchor           = common.trust_anchor ;
      own_random ;
      own_certificate        = common.own_certificate ;
      own_private_key        = common.own_private_key ;
      own_name               = common.own_name ;
      received_certificates  = common.received_certificates ;
      master_secret          = common.master_secret ;
      alpn_protocol          = common.alpn_protocol ;
      session_id             = Cstruct.empty ;
      extended_ms            = false ;
    } in
  epoch

let epoch_of_session server peer_name protocol_version = function
  | `TLS (session : session_data) ->
    let epoch = common_data_to_epoch session.common_session_data server peer_name in
    {
      epoch with
      protocol_version       = protocol_version ;
      ciphersuite            = session.ciphersuite ;
      session_id             = session.session_id ;
      extended_ms            = session.extended_ms ;
    }
  | `TLS13 (session : session_data13) ->
    let epoch : epoch_data = common_data_to_epoch session.common_session_data13 server peer_name in
    {
      epoch with
      ciphersuite            = (session.ciphersuite13 :> Ciphersuite.ciphersuite) ;
      extended_ms            = true ; (* RFC 8446, Appendix D, last paragraph *)
      state                  = session.state ;
    }

let epoch_of_hs hs =
  let server =
    match hs.machina with
    | Client _ | Client13 _ -> false
    | Server _ | Server13 _ -> true
  and peer_name = Config.(hs.config.peer_name)
  in
  match hs.session with
  | []           -> None
  | session :: _ -> Some (epoch_of_session server peer_name hs.protocol_version session)
