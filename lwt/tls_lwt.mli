
exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Packet.alert_type

module Unix : sig

  type t

  val close : t -> unit Lwt.t

  val server_of_fd : Tls.Config.server -> Lwt_unix.file_descr -> t Lwt.t
  val client_of_fd : Tls.Config.client -> host:string -> Lwt_unix.file_descr -> t Lwt.t

  val accept  : Tls.Config.server -> Lwt_unix.file_descr -> (t * Lwt_unix.sockaddr) Lwt.t
  val connect : Tls.Config.client -> string * int -> t Lwt.t

  val read   : t -> Cstruct.t      -> int  Lwt.t
  val write  : t -> Cstruct.t      -> unit Lwt.t
  val writev : t -> Cstruct.t list -> unit Lwt.t

  val read_bytes  : t -> Lwt_bytes.t -> int -> int -> int  Lwt.t
  val write_bytes : t -> Lwt_bytes.t -> int -> int -> unit Lwt.t

end

type ic = Lwt_io.input_channel
type oc = Lwt_io.output_channel

val accept_ext : Tls.Config.server -> Lwt_unix.file_descr ->
                 ((ic * oc) * Lwt_unix.sockaddr) Lwt.t

val accept : X509_lwt.priv -> Lwt_unix.file_descr ->
             ((ic * oc) * Lwt_unix.sockaddr) Lwt.t

val connect_ext : Tls.Config.client -> string * int -> (ic * oc) Lwt.t

val connect : X509_lwt.validator -> string * int -> (ic * oc) Lwt.t

val of_t : Unix.t -> ic * oc

val rng_init : ?rng_file:string -> unit -> unit Lwt.t
