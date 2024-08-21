(* Defines all high-level datatypes for the TLS library. It is opaque to clients
 of this library, and only used from within the library. *)

open Core
open Mirage_crypto

type hmac_key = string

(* initialisation vector style, depending on TLS version *)
type iv_mode =
  | Iv of string  (* traditional CBC (reusing last cipherblock) *)
  | Random_iv        (* TLS 1.1 and higher explicit IV (we use random) *)

type 'k cbc_cipher    = (module Block.CBC with type key = 'k)
type 'k cbc_state = {
  cipher         : 'k cbc_cipher ;
  cipher_secret  : 'k ;
  iv_mode        : iv_mode ;
  hmac           : Digestif.hash' ;
  hmac_secret    : hmac_key
}

type nonce = string

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
type hs_log = string list

type dh_secret = [
  | `Finite_field of Mirage_crypto_pk.Dh.secret
  | `P256 of Mirage_crypto_ec.P256.Dh.secret
  | `P384 of Mirage_crypto_ec.P384.Dh.secret
  | `P521 of Mirage_crypto_ec.P521.Dh.secret
  | `X25519 of Mirage_crypto_ec.X25519.secret
]

(* a collection of client and server verify bytes for renegotiation *)
type reneg_params = string * string

type common_session_data = {
  server_random          : string ; (* 32 bytes random from the server hello *)
  client_random          : string ; (* 32 bytes random from the client hello *)
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
  session_id             : string ;
  extended_ms            : bool ;
  tls_unique             : string ;
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
  | AwaitClientChangeCipherSpecResume of session_data * crypto_context * string * hs_log (* resumption: next should be change cipher spec *)
  | AwaitClientFinished of session_data * hs_log (* change cipher spec received, next should be the finished including a hmac over all handshake packets *)
  | AwaitClientFinishedResume of session_data * string * hs_log (* change cipher spec received, next should be the finished including a hmac over all handshake packets *)
  | Established (* handshake successfully completed *)

(* state machine of the client *)
type client_handshake_state =
  | ClientInitial (* initial state *)
  | AwaitServerHello of client_hello * (group * dh_secret) list * hs_log (* client hello is sent, handshake_params are half-filled *)
  | AwaitServerHelloRenegotiate of session_data * client_hello * hs_log (* client hello is sent, handshake_params are half-filled *)
  | AwaitCertificate_RSA of session_data * hs_log (* certificate expected with RSA key exchange *)
  | AwaitCertificate_DHE of session_data * hs_log (* certificate expected with DHE key exchange *)
  | AwaitServerKeyExchange_DHE of session_data * hs_log (* server key exchange expected with DHE *)
  | AwaitCertificateRequestOrServerHelloDone of session_data * string * string * hs_log (* server hello done expected, client key exchange and premastersecret are ready *)
  | AwaitServerHelloDone of session_data * signature_algorithm list option * string * string * hs_log (* server hello done expected, client key exchange and premastersecret are ready *)
  | AwaitServerChangeCipherSpec of session_data * crypto_context * string * hs_log (* change cipher spec expected *)
  | AwaitServerChangeCipherSpecResume of session_data * crypto_context * crypto_context * hs_log (* change cipher spec expected *)
  | AwaitServerFinished of session_data * string * hs_log (* finished expected with a hmac over all handshake packets *)
  | AwaitServerFinishedResume of session_data * hs_log (* finished expected with a hmac over all handshake packets *)
  | Established (* handshake successfully completed *)

type kdf = {
  secret : string ;
  cipher : Ciphersuite.ciphersuite13 ;
  hash : Digestif.hash' ;
}

(* TODO needs log of CH..CF for post-handshake auth *)
(* TODO drop master_secret!? *)
type session_data13 = {
  common_session_data13  : common_session_data ;
  ciphersuite13          : Ciphersuite.ciphersuite13 ;
  master_secret          : kdf ;
  exporter_master_secret : string ;
  resumption_secret      : string ;
  state                  : epoch_state ;
  resumed                : bool ;
  client_app_secret      : string ;
  server_app_secret      : string ;
}

type client13_handshake_state =
  | AwaitServerHello13 of client_hello * (group * dh_secret) list * string (* this is for CH1 ~> HRR ~> CH2 <~ WAIT SH *)
  | AwaitServerEncryptedExtensions13 of session_data13 * string * string * string
  | AwaitServerCertificateRequestOrCertificate13 of session_data13 * string * string * string
  | AwaitServerCertificate13 of session_data13 * string * string * signature_algorithm list option * string
  | AwaitServerCertificateVerify13 of session_data13 * string * string * signature_algorithm list option * string
  | AwaitServerFinished13 of session_data13 * string * string * signature_algorithm list option * string
  | Established13

type server13_handshake_state =
  | AwaitClientHelloHRR13 (* if we sent out HRR (also to-be-used for tls13-only) *)
  | AwaitClientCertificate13 of session_data13 * string * crypto_context * session_ticket option * string
  | AwaitClientCertificateVerify13 of session_data13 * string * crypto_context * session_ticket option * string
  | AwaitClientFinished13 of string * crypto_context * session_ticket option * string
  | AwaitEndOfEarlyData13 of string * crypto_context * crypto_context * session_ticket option * string
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
  hs_fragment      : string ; (* handshake messages can be fragmented, leftover from before *)
}

(* connection state: initially None, after handshake a crypto context *)
type crypto_state = crypto_context option

(* record consisting of a content type and a byte vector *)
type record = Packet.content_type * string

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
  fragment  : string ; (* the leftover fragment from TCP fragmentation *)
  read_closed : bool ;
  write_closed : bool ;
}

type error = [
  | `AuthenticationFailure of X509.Validation.validation_error
  | `NoConfiguredCiphersuite of Ciphersuite.ciphersuite list
  | `NoConfiguredVersions of tls_version list
  | `NoConfiguredSignatureAlgorithm of signature_algorithm list
  | `NoMatchingCertificateFound of string
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
  | `CouldntSelectCertificate -> Fmt.string ppf "couldn't select certificate"

type fatal = [
  | `Protocol_version of [
      | `None_supported of tls_any_version list
      | `Unknown_record of int * int
      | `Bad_record of tls_any_version
    ]
  | `Unexpected of [
      | `Content_type of int
      | `Message of string
      | `Handshake of tls_handshake
    ]
  | `Decode of string
  | `Handshake of [
      | `Message of string
      | `Fragments
      | `BadDH of string
      | `BadECDH of Mirage_crypto_ec.error
    ]
  | `Bad_certificate of string
  | `Missing_extension of string
  | `Bad_mac
  | `Record_overflow of int
  | `Unsupported_extension
  | `Inappropriate_fallback
  | `No_application_protocol
]

let pp_protocol_version ppf = function
  | `None_supported vs ->
    Fmt.pf ppf "none supported, client provided %a"
      Fmt.(list ~sep:(any ", ") pp_tls_any_version) vs
  | `Unknown_record (maj, min) ->
    Fmt.pf ppf "unknown record version %u.%u" maj min
  | `Bad_record v ->
    Fmt.pf ppf "bad record version %a" pp_tls_any_version v

let pp_unexpected ppf = function
  | `Content_type c -> Fmt.pf ppf "content type %u" c
  | `Message msg -> Fmt.string ppf msg
  | `Handshake hs -> Fmt.pf ppf "handshake %a" pp_handshake hs

let pp_handshake_error ppf = function
  | `Message msg -> Fmt.string ppf msg
  | `Fragments -> Fmt.string ppf "fragments are not empty"
  | `BadDH msg -> Fmt.pf ppf "bad DH %s" msg
  | `BadECDH e -> Fmt.pf ppf "bad ECDH %a" Mirage_crypto_ec.pp_error e

let pp_fatal ppf = function
  | `Protocol_version e -> Fmt.pf ppf "version error: %a" pp_protocol_version e
  | `Unexpected p -> Fmt.pf ppf "unexpected: %a" pp_unexpected p
  | `Decode msg -> Fmt.pf ppf "decode error: %s" msg
  | `Handshake h -> Fmt.pf ppf "handshake error: %a" pp_handshake_error h
  | `Bad_certificate msg -> Fmt.pf ppf "bad certificate: %s" msg
  | `Missing_extension msg -> Fmt.pf ppf "missing extension: %s" msg
  | `Bad_mac -> Fmt.string ppf "MAC mismatch"
  | `Record_overflow n -> Fmt.pf ppf "record overflow %u" n
  | `Unsupported_extension -> Fmt.string ppf "unsupported extension"
  | `Inappropriate_fallback -> Fmt.string ppf "inappropriate fallback"
  | `No_application_protocol -> Fmt.string ppf "no application protocol"

type failure = [
  | `Error of error
  | `Fatal of fatal
  | `Alert of Packet.alert_type
]

let pp_failure ppf = function
  | `Error e -> pp_error ppf e
  | `Fatal f -> pp_fatal ppf f
  | `Alert a -> Fmt.pf ppf "alert %s" (Packet.alert_type_to_string a)

let common_data_to_epoch common is_server peer_name =
  let own_random, peer_random =
    if is_server then
      common.server_random, common.client_random
    else
      common.client_random, common.server_random
  in
  let epoch : epoch_data =
    { side                   = if is_server then `Server else `Client ;
      state                  = `Established ;
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
      exporter_master_secret = "" ;
      alpn_protocol          = common.alpn_protocol ;
      session_id             = "" ;
      extended_ms            = false ;
      tls_unique             = None ;
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
      tls_unique             = Some session.tls_unique ;
    }
  | `TLS13 (session : session_data13) ->
    let epoch : epoch_data = common_data_to_epoch session.common_session_data13 server peer_name in
    {
      epoch with
      protocol_version       = protocol_version ;
      ciphersuite            = (session.ciphersuite13 :> Ciphersuite.ciphersuite) ;
      extended_ms            = true ; (* RFC 8446, Appendix D, last paragraph *)
      state                  = session.state ;
      exporter_master_secret = session.exporter_master_secret ;
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
