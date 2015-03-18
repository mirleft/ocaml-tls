(** Core of pure library. This is the interface to effectful front-ends. *)

(** failures which can be mitigated by reconfiguration *)
type error = [
  | `AuthenticationFailure of X509.Validation.certificate_failure
  | `NoConfiguredCiphersuite of Ciphersuite.ciphersuite list
  | `NoConfiguredVersion of Core.tls_version
  | `NoConfiguredHash of Nocrypto.Hash.hash list
  | `NoSecureRenegotiation
  | `NoMatchingCertificateFound of string
  | `NoCertificateConfigured
  | `CouldntSelectCertificate
]

(** failures from received garbage or lack of features *)
type fatal = [
  | `NoCiphersuite of Packet.any_ciphersuite list
  | `NoVersion of Core.tls_any_version
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
  | `BadRecordVersion of Core.tls_any_version
  | `BadFinished
  | `HandshakeFragmentsNotEmpty
  | `InvalidDH
  | `MixedCiphersuites
  | `InvalidRenegotiation
  | `InvalidClientHello
  | `InvalidServerHello
  | `InvalidRenegotiationVersion of Core.tls_version
  | `InappropriateFallback
  | `UnexpectedCCS
  | `UnexpectedHandshake of Core.tls_handshake
  | `InvalidCertificateUsage
  | `InvalidCertificateExtendedUsage
  | `InvalidSession
]

(** type of failures *)
type failure = [
  | `Error of error
  | `Fatal of fatal
] with sexp

(** convert a failure to a tls alert *)
val alert_of_failure : failure -> Packet.alert_type

(** convert a failure to a string *)
val string_of_failure : failure -> string

(** some abstract type a client gets *)
type state

(** return type of handle_tls *)
type ret = [

  | `Ok of [ `Ok of state | `Eof | `Alert of Packet.alert_type ]
         * [ `Response of Cstruct.t option ]
         * [ `Data of Cstruct.t option ]
 (** success with either a new state, end of file, or an alert, a response to the communication partner and potential data for the application *)

  | `Fail of failure * [ `Response of Cstruct.t ] (** fail with a failure, and a response to the other side *)
]

(** [handle_tls tls in] is [ret], depending on incoming [tls] state and cstruct, return appropriate [ret] *)
val handle_tls : state -> Cstruct.t -> ret

(** [can_handle_appdata tls] is a predicate which indicates when the connection has already completed a handshake *)
val can_handle_appdata    : state -> bool

(** [handshake_in_progress tls] is a predicate which indicates whether a handshake is in progress *)
val handshake_in_progress : state -> bool

(** [send_application_data tls outs] is [(tls' * out) option] where [tls'] is the new tls state, and [out] the cstruct to send over the wire (encrypted and wrapped [outs]) *)
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

(** [send_close_notify tls] is [tls' * out] where [tls'] is the new tls state, and out the (possible encrypted) close notify alert *)
val send_close_notify     : state -> state * Cstruct.t

(** [reneg tls] is [(tls' * out) option] where [tls'] is the new tls state, and out either a client hello or hello request (depending on the communication endpoint we are) *)
val reneg                 : state -> (state * Cstruct.t) option

(** [client client] is [tls * out] where [tls] is the initial state, and [out] the initial client hello *)
val client : Config.client -> (state * Cstruct.t)

(** [server server] is [tls] where [tls] is the initial server state *)
val server : Config.server -> state

type epoch_data = {
  protocol_version : Core.tls_version ;
  ciphersuite      : Ciphersuite.ciphersuite ;
  peer_certificate : X509.t list ;
  peer_name        : string option ;
  trust_anchor     : X509.t option ;
  own_certificate  : X509.t list ;
  own_private_key  : Nocrypto.Rsa.priv option ;
  own_name         : string option ;
  master_secret    : State.master_secret ;
} with sexp

type epoch = [
  | `InitialEpoch
  | `Epoch of epoch_data
] with sexp

val epoch : state -> epoch
