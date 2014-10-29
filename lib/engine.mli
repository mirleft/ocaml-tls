(** Core of pure library. This is the interface to effectful front-ends. *)

(** type of alerts *)
type alert = Packet.alert_type

(** some abstract type a client gets *)
type state

(** return type of handle_tls *)
type ret = [

  | `Ok of [ `Ok of state | `Eof | `Alert of alert ]
         * [ `Response of Cstruct.t option ]
         * [ `Data of Cstruct.t option ]
 (** success with either a new state, end of file, or an alert, a response to the communication partner and potential data for the application *)

  | `Fail of alert * [ `Response of Cstruct.t ] (** failure with an alert, and a response to the other side *)
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
  peer_certificate : Certificate.certificate list ;
  peer_name        : string option ;
  trust_anchor     : Certificate.certificate option ;
  own_certificate  : Certificate.certificate list ;
  own_private_key  : Nocrypto.Rsa.priv option ;
  own_name         : string option ;
  master_secret    : State.master_secret ;
} with sexp

type epoch = [
  | `InitialEpoch
  | `Epoch of epoch_data
] with sexp

val epoch : state -> epoch
