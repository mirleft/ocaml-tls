
exception Tls_alert of Tls.Packet.alert_type

type o_server = X509_lwt.priv
type o_client = X509_lwt.validator

module Unix : sig

  type t

  val close : t -> unit Lwt.t

  val server_of_fd : o_server ->                Lwt_unix.file_descr -> t Lwt.t
  val client_of_fd : o_client -> host:string -> Lwt_unix.file_descr -> t Lwt.t

  val accept  : o_server -> Lwt_unix.file_descr -> (t * Lwt_unix.sockaddr) Lwt.t
  val connect : o_client -> string * int -> t Lwt.t

  val read   : t -> Cstruct.t      -> int  Lwt.t
  val write  : t -> Cstruct.t      -> unit Lwt.t
  val writev : t -> Cstruct.t list -> unit Lwt.t

  val read_bytes  : t -> Lwt_bytes.t -> int -> int -> int  Lwt.t
  val write_bytes : t -> Lwt_bytes.t -> int -> int -> unit Lwt.t

end

type ic = Lwt_io.input_channel
type oc = Lwt_io.output_channel

val accept : o_server -> Lwt_unix.file_descr
                      -> ((ic * oc) * Lwt_unix.sockaddr) Lwt.t
val connect : o_client -> string * int -> (ic * oc) Lwt.t

val of_t : Unix.t -> ic * oc
