
exception Tls_alert of Tls.Packet.alert_type

type t

type o_server = X509_lwt.priv
type o_client = X509_lwt.validator

val read   : t -> Cstruct.t      -> int  Lwt.t
val write  : t -> Cstruct.t      -> unit Lwt.t
val writev : t -> Cstruct.t list -> unit Lwt.t

val close : t -> unit Lwt.t

val server_of_fd : o_server ->                Lwt_unix.file_descr -> t Lwt.t
val client_of_fd : o_client -> host:string -> Lwt_unix.file_descr -> t Lwt.t

val accept  : o_server -> Lwt_unix.file_descr -> (t * Lwt_unix.sockaddr) Lwt.t
val connect : o_client -> string * int -> t Lwt.t

