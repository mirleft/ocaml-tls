
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

  module type RW = sig
    type buf
    val read   : t -> buf      -> int  Lwt.t
    val write  : t -> buf      -> unit Lwt.t
    val writev : t -> buf list -> unit Lwt.t
  end
  module Cstruct : RW with type buf = Cstruct.t
  module Bytes   : RW with type buf = Lwt_bytes.t * int * int
end
