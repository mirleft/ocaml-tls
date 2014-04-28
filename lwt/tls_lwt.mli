
exception Tls_alert of Tls.Packet.alert_type

type socket

val resolve : string -> string -> Unix.sockaddr Lwt.t

val read   : socket -> Cstruct.t Lwt.t
val write  : socket -> Cstruct.t      -> unit Lwt.t
val writev : socket -> Cstruct.t list -> unit Lwt.t

val server_of_fd : ?cert:X509_lwt.priv
                -> Lwt_unix.file_descr
                -> socket Lwt.t

val client_of_fd : ?cert:X509_lwt.priv
                -> ?host:string
                -> validator:X509_lwt.validator
                -> Lwt_unix.file_descr
                -> socket Lwt.t

val accept : ?cert:X509_lwt.priv
          -> Lwt_unix.file_descr
          -> (socket * Lwt_unix.sockaddr) Lwt.t

val connect : ?cert:X509_lwt.priv
           -> validator:X509_lwt.validator
           -> host:string
           -> port:string
           -> socket Lwt.t

