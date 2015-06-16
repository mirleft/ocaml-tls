(** Transport layer security core.

    [TLS] implements the transport layer security protocol entirely in
    OCaml.  TLS is used to secure a session between two endpoints, a
    client and a server.  This session can either be not authenticated
    at all, or either, or both endpoints can be authenticated.  Most
    common is that the server is authenticated using X.509
    certificates.

    TLS is algorithmically agile: protocol version, key exchange
    algorithm, symmetric cipher, and message authentication code are
    negotiated upon connection.

    This module [Engine] provides the pure core of the protocol
    handling, and is used by the effectful front-ends. *)

(** {1 Constructors} *)

(** The abstract [state] type. *)
type state

(** [client client] is [tls * out] where [tls] is the initial state,
    and [out] the initial client hello *)
val client : Config.client -> (state * Cstruct.t)

(** [server server] is [tls] where [tls] is the initial server
    state *)
val server : Config.server -> state

(** {1 Protocol failures} *)

(** failures which can be mitigated by reconfiguration *)
type error = [
  | `AuthenticationFailure of X509.Validation.validation_error
  | `NoConfiguredCiphersuite of Ciphersuite.ciphersuite list
  | `NoConfiguredVersion of Core.tls_version
  | `NoConfiguredHash of Nocrypto.Hash.hash list
  | `NoMatchingCertificateFound of string
  | `NoCertificateConfigured
  | `CouldntSelectCertificate
]

(** failures from received garbage or lack of features *)
type fatal = [
  | `NoSecureRenegotiation
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
]

(** [alert_of_failure failure] is [alert], the TLS alert type for this failure. *)
val alert_of_failure : failure -> Packet.alert_type

(** [string_of_failure failure] is [string], the string representation of the [failure]. *)
val string_of_failure : failure -> string

(** [failure_of_sexp sexp] is [failure], the unmarshalled [sexp]. *)
val failure_of_sexp : Sexplib.Sexp.t -> failure

(** [sexp_of_failure failure] is [sexp], the marshalled [failure]. *)
val sexp_of_failure : failure -> Sexplib.Sexp.t

(** {1 Protocol handling} *)

(** return type of {!handle_tls}: either failed to handle the incoming
    buffer ([`Fail]) with {!failure} and potentially a message to send
    to the other endpoint, or sucessful operation ([`Ok]) with a new
    {!state}, an end of file ([`Eof]), or an incoming ([`Alert]).
    Possibly some [`Response] to the other endpoint is needed, and
    potentially some [`Data] for the application was received. *)
type ret = [
  | `Ok of [ `Ok of state | `Eof | `Alert of Packet.alert_type ]
         * [ `Response of Cstruct.t option ]
         * [ `Data of Cstruct.t option ]
  | `Fail of failure * [ `Response of Cstruct.t ]
]

(** [handle_tls state buffer] is [ret], depending on incoming [state]
    and [buffer], return appropriate {!ret} *)
val handle_tls           : state -> Cstruct.t -> ret

(** [can_handle_appdata state] is a predicate which indicates when the
    connection has already completed a handshake. *)
val can_handle_appdata    : state -> bool

(** [handshake_in_progress tls] is a predicate which indicates whether
    a handshake is in progress. *)
val handshake_in_progress : state -> bool

(** [send_application_data tls outs] is [(tls' * out) option] where
    [tls'] is the new tls state, and [out] the cstruct to send over the
    wire (encrypted and wrapped [outs]) *)
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

(** [send_close_notify tls] is [tls' * out] where [tls'] is the new
    tls state, and out the (possible encrypted) close notify alert *)
val send_close_notify     : state -> state * Cstruct.t

(** [reneg tls] is [(tls' * out) option] where [tls'] is the new tls
    state, and out either a client hello or hello request (depending on
    the communication endpoint we are) *)
val reneg                 : state -> (state * Cstruct.t) option

(** {1 Session information} *)

(** polymorphic variant, only the second should ever be visible to an
    application. *)
type epoch = [
  | `InitialEpoch
  | `Epoch of Core.epoch_data
]

(** [epoch_of_sexp sexp] is [epoch], the unmarshalled [sexp]. *)
val epoch_of_sexp : Sexplib.Sexp.t -> epoch

(** [sexp_of_epoch epoch] is [sexp], the marshalled [epoch]. *)
val sexp_of_epoch : epoch -> Sexplib.Sexp.t

(** [epoch state] is [epoch], which contains the session
    information. *)
val epoch : state -> epoch
