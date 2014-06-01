open Core
open State

type state = State.state

type role = [ `Server | `Client ]

(*
type alert  = Packet.alert_type

type output = Cstruct.t * Cstruct.t option

type result = [
  | `Ok    of state
  | `Alert of alert
  | `Fail  of alert
] 

type ret = result * output
*)

type ret = [
  | `Ok   of [ `Ok of state | `Alert of Packet.alert_type ] * Cstruct.t * Cstruct.t option
  | `Fail of Packet.alert_type * Cstruct.t
]

val new_state : Config.config -> role -> state

val can_handle_appdata : state -> bool
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

val handle_tls : state -> Cstruct.t -> ret

val open_connection' : Config.config -> (state * Cstruct.t)
val open_connection : ?cert:Config.own_cert -> ?host:string -> validator:X509.Validator.t -> unit -> (state * Cstruct.t)
val listen_connection : ?cert:Config.own_cert -> unit -> state
