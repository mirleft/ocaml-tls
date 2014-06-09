open Core
open State

type state = State.state

type ret = [
  | `Ok   of [ `Ok of state | `Eof | `Alert of Packet.alert_type ] * Cstruct.t * Cstruct.t option
  | `Fail of Packet.alert_type * Cstruct.t
]

val can_handle_appdata    : state -> bool
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option
val send_close_notify     : state -> state * Cstruct.t
val rekey                 : state -> (state * Cstruct.t) option

val handle_tls : state -> Cstruct.t -> ret

val client : Config.client -> (state * Cstruct.t)
val server : Config.server -> state
