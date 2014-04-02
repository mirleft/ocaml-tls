
exception Tls_alert of Tls.Packet.alert_type

type socket

val resolve : string -> string -> Unix.sockaddr Lwt.t

val read     : socket -> Cstruct.t Lwt.t
val write    : socket -> Cstruct.t -> unit Lwt.t
val writev   : socket -> Cstruct.t list -> unit Lwt.t

val server_of_fd : Lwt_unix.file_descr -> socket Lwt.t
val client_of_fd : ?servername:string -> Lwt_unix.file_descr -> socket Lwt.t

val accept  : Lwt_unix.file_descr -> (socket * Lwt_unix.sockaddr) Lwt.t
val connect : ?fd:Lwt_unix.file_descr -> Lwt_unix.sockaddr -> socket Lwt.t

