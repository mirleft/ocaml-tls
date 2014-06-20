(** Core of pure library. This is the interface to effectful front-ends. *)

(** the alert type *)
type alert = Packet.alert_type

(** some abstract type a client gets *)
type state

(** return type of handle_tls *)
type ret = [

  | `Ok of [ `Ok of state | `Eof | `Alert of alert ]
         * [ `Response of Cstruct.t ]
         * [ `Data of Cstruct.t option ]
 (** success with either a new state, end of file, or an alert, a response to the communication partner and potential data for the application *)

  | `Fail of alert * [ `Response of Cstruct.t ] (** failure with an alert, and a response to the other side *)
]

(** the main pure handler: state and packet in, return out *)
val handle_tls : state -> Cstruct.t -> ret

(** predicate whether connection is already secure *)
val can_handle_appdata    : state -> bool

val handshake_in_progress : state -> bool

(** use the current state to prepare a list of cstructs for sending, resulting in a new state and an outgoing cstruct *)
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

(** close the connection by preparing a close notify to the other end *)
val send_close_notify     : state -> state * Cstruct.t

(** start rekeying of the connection *)
val rekey                 : state -> (state * Cstruct.t) option

(** given a config, create an initial state and outgoing client hello *)
val client : Config.client -> (state * Cstruct.t)

(** given a config, create an initial server state *)
val server : Config.server -> state
