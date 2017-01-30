(** Transport layer security

    [TLS] is an implementation of
    {{:https://en.wikipedia.org/wiki/Transport_Layer_Security}transport
    layer security} in OCaml.  TLS is a widely used security protocol
    which establishes an end-to-end secure channel (with optional
    (mutual) authentication) between two endpoints.  It uses TCP/IP as
    transport.  This library supports all three versions of TLS:
    {{:https://tools.ietf.org/html/rfc5246}1.2, RFC5246},
    {{:https://tools.ietf.org/html/rfc4346}1.1, RFC4346}, and
    {{:https://tools.ietf.org/html/rfc2246}1.0, RFC2246}.  SSL, the
    previous protocol definition, is not supported.

    TLS is algorithmically agile: protocol version, key exchange
    algorithm, symmetric cipher, and message authentication code are
    negotiated upon connection.

    This library implements several extensions of TLS,
    {{:https://tools.ietf.org/html/rfc3268}AES ciphers},
    {{:https://tools.ietf.org/html/rfc4366}TLS extensions} (such as
    server name indication, SNI),
    {{:https://tools.ietf.org/html/rfc5746}Renegotiation extension},
    {{:https://tools.ietf.org/html/rfc7627}Session Hash and Extended
    Master Secret Extension}.

    This library does not contain insecure cipher suites (such as
    single DES, export ciphers, ...).  It does not expose the server
    time in the server random, requires secure renegotiation.

    This library consists of a core, implemented in a purely
    functional matter ({!Engine}, this module), and effectful parts:
    {!Tls_lwt} and {!Tls_mirage}.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}} *)


(** {1 Abstract state type} *)

(** The abstract type of a TLS state, with
    {{!Encoding.Pem.Certificate}encoding and decoding to PEM}. *)
type state

(** {1 Constructors} *)

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
  | `NoConfiguredVersion of Types.tls_version
  | `NoConfiguredHash of Nocrypto.Hash.hash list
  | `NoMatchingCertificateFound of string
  | `NoCertificateConfigured
  | `CouldntSelectCertificate
]

(** failures from received garbage or lack of features *)
type fatal = [
  | `NoSecureRenegotiation
  | `NoCiphersuite of Packet.any_ciphersuite list
  | `NoVersion of Types.tls_any_version
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
  | `BadRecordVersion of Types.tls_any_version
  | `BadFinished
  | `HandshakeFragmentsNotEmpty
  | `InvalidDH
  | `InvalidRenegotiation
  | `InvalidClientHello
  | `InvalidServerHello
  | `InvalidRenegotiationVersion of Types.tls_version
  | `InappropriateFallback
  | `UnexpectedCCS
  | `UnexpectedHandshake of Types.tls_handshake
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

(** result type of {!handle_tls}: either failed to handle the incoming
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
    and [buffer], the result is the appropriate {!ret} *)
val handle_tls           : state -> Cstruct.t -> ret

(** [can_handle_appdata state] is a predicate which indicates when the
    connection has already completed a handshake. *)
val can_handle_appdata    : state -> bool

(** [send_application_data tls outs] is [(tls' * out) option] where
    [tls'] is the new tls state, and [out] the cstruct to send over the
    wire (encrypted [outs]). *)
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

(** [send_close_notify tls] is [tls' * out] where [tls'] is the new
    tls state, and out the (possible encrypted) close notify alert. *)
val send_close_notify     : state -> state * Cstruct.t

(** [reneg tls] initiates a renegotation on [tls]. It is [tls' * out]
    where [tls'] is the new tls state, and [out] either a client hello
    or hello request (depending on which communication endpoint [tls]
    is). *)
val reneg                 : state -> (state * Cstruct.t) option

(** {1 Session information} *)

(** polymorphic variant of session information.  The first variant
    [`InitialEpoch] will only be used for TLS states without completed
    handshake.  The second variant, [`Epoch], contains actual session
    data. *)
type epoch = [
  | `InitialEpoch
  | `Epoch of Types.epoch_data
]

(** [epoch_of_sexp sexp] is [epoch], the unmarshalled [sexp]. *)
val epoch_of_sexp : Sexplib.Sexp.t -> epoch

(** [sexp_of_epoch epoch] is [sexp], the marshalled [epoch]. *)
val sexp_of_epoch : epoch -> Sexplib.Sexp.t

(** [epoch state] is [epoch], which contains the session
    information. *)
val epoch : state -> epoch
