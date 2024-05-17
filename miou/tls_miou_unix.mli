(** Effectful operations using Miou for pure TLS.

    The pure TLS is state and buffer in, state and buffer out. This module uses
    Miou (and its Unix layer) for communication over the network. *)

exception Tls_alert of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure
exception Closed_by_peer

type t
(** Abstract type of a session. *)

val file_descr : t -> Miou_unix.file_descr
(** [file_descr] returns the underlying file-descriptor used by the given
    TLS {i socket}. *)

val read : t -> ?off:int -> ?len:int -> bytes -> int
(** [read fd buf ~off ~len] reads up to [len] bytes (defaults to
    [Bytes.length buf - off] from the given TLS {i socket} [fd], storing them in
    byte sequence [buf], starting at position [off] in [buf] (defaults to [0]).
    It returns the actual number of characters read, between 0 and [len]
    (inclusive).

    @raise Unix_error raised by the system call {!val:Unix.read}. The function
    handles {!val:Unix.EINTR}, {!val:Unix.EAGAIN} and {!val:Unix.EWOULDBLOCK}
    exceptions and redo the system call.

    @raise Invalid_argument if [off] and [len] do not designate a valid range of
    [buf]. *)

val really_read : t -> ?off:int -> ?len:int -> bytes -> unit
(** [really_read fd buf ~off ~len] reads [len] bytes (defaults to
    [Bytes.length buf - off]) from the given TLS {i socket} [fd], storing them
    in byte sequence [buf], starting at position [off] in [buf] (defaults to
    [0]). If [len = 0], [really_read] does nothing.

    @raise Unix_error raised by the system call {!val:Unix.read}. The function
    handles {!val:Unix.EINTR}, {!val:Unix.EAGAIN} and {!val:Unix.EWOULDBLOCK}
    exceptions and redo the system call.

    @raise End_of_file if {!val:Unix.read} returns [0] before [len] characters
    have been read.

    @raise Invalid_argument if [off] and [len] do not designate a valid range of
    [buf]. *)

val write : t -> ?off:int -> ?len:int -> string -> unit
(** [write t str ~off ~len] writes [len] bytes (defaults to
    [String.length str - off]) from byte sequence [str], starting at offset
    [off] (defaults to [0]), to the given TLS {i socket} [fd].

    @raise Unix_error raised by the syscall call {!val:Unix.write}. The function
    handles {!val:Unix.EINTR}, {!val:Unix.EAGAIN} and {!val:Unix.EWOULDBLOCK}
    exceptions and redo the system call.

    @raise Closed_by_peer if [t] is connected to a peer whose reading end is
    closed. Similar to the {!val:EPIPE} error for pipe/socket connected.

    @raise Invalid_argument if [off] and [len] do not designate a valid range of
    [buf]. *)

val close : t -> unit
(** [close flow] closes the TLS session and the underlying file-descriptor. *)

val shutdown : t -> [ `read | `write | `read_write ] -> unit
(** [shutdown t direction] closes the direction of the TLS session [t]. If
    [`read_write] or [`write] is closed, a TLS close-notify is sent to the other
    endpoint. If this results in a fully-closed session (or an errorneous
    session), the underlying file descriptor is closed. *)

val client_of_fd :
  Tls.Config.client ->
  ?read_buffer_size:int ->
  ?host:[ `host ] Domain_name.t ->
  Miou_unix.file_descr ->
  t
(** [client_of_flow client ~host fd] is [t], after client-side TLS handshake of
    [fd] using [client] configuration and [host].

    @raise End_of_file if we are not able to complete the handshake. *)

val server_of_fd :
  Tls.Config.server -> ?read_buffer_size:int -> Miou_unix.file_descr -> t
(** [server_of_fd server fd] is [t], after server-side TLS handshake of [fd]
    using [server] configuration.

    @raise End_of_file if we are not able to complete the handshake. *)

val connect : X509.Authenticator.t -> string * int -> t
(** [connect authenticator (host, port)] is [t], a connected TLS connection
    to [host] on [port] using the default configuration and the
    [authenticator]. *)

val epoch : t -> Tls.Core.epoch_data option
(** [epoch t] returns [epoch], which contains information of the active
    session. *)
