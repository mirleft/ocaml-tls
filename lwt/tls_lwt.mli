
exception Tls_alert of Tls.Packet.alert_type

type socket

val resolve : string -> string -> Unix.sockaddr Lwt.t

val read     : socket -> Cstruct.t Lwt.t
val write    : socket -> Cstruct.t -> unit Lwt.t
val writev   : socket -> Cstruct.t list -> unit Lwt.t

val server_of_fd : ?cert:X509_lwt.cert -> Lwt_unix.file_descr -> socket Lwt.t
val client_of_fd : ?cert:X509_lwt.cert -> validator:Tls.X509.Validator.t -> ?host:string -> Lwt_unix.file_descr -> socket Lwt.t

val accept  : ?cert:X509_lwt.cert -> Lwt_unix.file_descr -> (socket * Lwt_unix.sockaddr) Lwt.t
val connect : ?fd:Lwt_unix.file_descr -> ?cert:X509_lwt.cert -> validator:Tls.X509.Validator.t -> host:string -> port:string -> socket Lwt.t
