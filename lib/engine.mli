open Handshake_common_utils
open Handshake_common_utils.Or_alert
open Core

type role = [ `Server | `Client ]

type state = {
  handshake : tls_internal_state ;
  decryptor : crypto_state ;
  encryptor : crypto_state ;
  fragment  : Cstruct.t ;
}

type ret = [
  | `Ok   of state * Cstruct.t * Cstruct.t option
  | `Fail of Packet.alert_type * Cstruct.t
]

val new_state : Config.config -> role -> state

val can_send_appdata : state -> bool
val send_application_data : state -> Cstruct.t list -> (state * Cstruct.t) option

val handle_tls : state -> Cstruct.t -> ret
val open_connection' : Config.config -> (state * Cstruct.t)
val open_connection : ?cert:Config.own_cert -> ?host:string -> validator:X509.Validator.t -> unit -> (state * Cstruct.t)
val listen_connection : ?cert:Config.own_cert -> unit -> state


val encrypt   : tls_version -> crypto_state -> Packet.content_type -> Cstruct.t -> (crypto_state * Cstruct.t)
val decrypt   : tls_version -> crypto_state -> Packet.content_type -> Cstruct.t -> (crypto_state * Cstruct.t) or_error

val separate_records : Cstruct.t -> ((tls_hdr * Cstruct.t) list * Cstruct.t) or_error
val handle_raw_record : state -> (tls_hdr * Cstruct.t) -> (state * Cstruct.t option * record list) or_error
val assemble_records : tls_version -> record list -> Cstruct.t
val send_records : state -> record list -> (state * Cstruct.t)
