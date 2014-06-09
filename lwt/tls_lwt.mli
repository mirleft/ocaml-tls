
exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Packet.alert_type

type tracer = Sexplib.Sexp.t -> unit

module Unix : sig

  type t

  val close : t -> unit Lwt.t

  val server_of_fd : ?trace:tracer -> Tls.Config.server -> Lwt_unix.file_descr -> t Lwt.t
  val client_of_fd : ?trace:tracer -> Tls.Config.client -> host:string -> Lwt_unix.file_descr -> t Lwt.t

  val accept  : ?trace:tracer -> Tls.Config.server -> Lwt_unix.file_descr -> (t * Lwt_unix.sockaddr) Lwt.t
  val connect : ?trace:tracer -> Tls.Config.client -> string * int -> t Lwt.t

  val read   : t -> Cstruct.t      -> int  Lwt.t
  val write  : t -> Cstruct.t      -> unit Lwt.t
  val writev : t -> Cstruct.t list -> unit Lwt.t

  val read_bytes  : t -> Lwt_bytes.t -> int -> int -> int  Lwt.t
  val write_bytes : t -> Lwt_bytes.t -> int -> int -> unit Lwt.t

end

type ic = Lwt_io.input_channel
type oc = Lwt_io.output_channel

val accept_ext :
  ?trace:tracer -> Tls.Config.server -> Lwt_unix.file_descr ->
  ((ic * oc) * Lwt_unix.sockaddr) Lwt.t

val accept :
  ?trace:tracer -> X509_lwt.priv -> Lwt_unix.file_descr ->
  ((ic * oc) * Lwt_unix.sockaddr) Lwt.t

val connect_ext :
  ?trace:tracer -> Tls.Config.client -> string * int -> (ic * oc) Lwt.t

val connect :
  ?trace:tracer -> X509_lwt.validator -> string * int -> (ic * oc) Lwt.t

val of_t : Unix.t -> ic * oc

val rng_init : ?rng_file:string -> unit -> unit Lwt.t
