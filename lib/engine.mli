
type state

type alert = Packet.alert_type

type ret = [

  | `Ok of [ `Ok of state | `Eof | `Alert of alert ]
         * [ `Response of Cstruct.t ]
         * [ `Data of Cstruct.t option ]

  | `Fail of alert * [ `Response of Cstruct.t ]
]

val can_handle_appdata    : state -> bool
val handshake_in_progress : state -> bool
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option
val send_close_notify     : state -> state * Cstruct.t
val rekey                 : state -> (state * Cstruct.t) option

val handle_tls : state -> Cstruct.t -> ret

val client : Config.client -> (state * Cstruct.t)
val server : Config.server -> state
