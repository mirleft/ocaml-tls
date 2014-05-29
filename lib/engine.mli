open Core
open State

type state = State.state

type role = [ `Server | `Client ]

type ret = [
  | `Ok   of state * Cstruct.t * Cstruct.t option
  | `Fail of Packet.alert_type * Cstruct.t
]

val new_state : Config.config -> role -> state

val can_handle_appdata : state -> bool
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

val handle_tls : state -> Cstruct.t -> ret

val open_connection' : Config.config -> (state * Cstruct.t)
val open_connection : ?cert:Config.own_cert -> ?host:string -> validator:X509.Validator.t -> unit -> (state * Cstruct.t)
val listen_connection : ?cert:Config.own_cert -> unit -> state
