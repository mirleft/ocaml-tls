open Core_kernel.Std
open Async.Std

(** Effectful operations using Async for pure TLS.

    The pure TLS is state and buffer in, state and buffer out.  This
    module uses Lwt for communication over the network.

    This module implements a high-level API and a low-level API (in
    {!Unix}).  Most applications should use the high-level API described below. *)

(** [Tls_alert] exception received from the other endpoint *)
exception Tls_alert   of Tls.Packet.alert_type

(** [Tls_failure] exception while processing incoming data *)
exception Tls_failure of Tls.Engine.failure

(** tracing of TLS sessions *)
type tracer = Sexplib.Sexp.t -> unit

(** Low-level API *)
module Unix : sig

  (** {1 Unix API} *)

  (** It is the responsibility of the client to handle error
      conditions.  The underlying file descriptors are not closed. *)

  (** Abstract type of a session *)
  type t

  (** {2 Constructors} *)
  (** [server_of_fd ?tracer server r w] is [t], after server-side TLS
      handshake using [server] configuration. *)
  val create_server : ?trace:tracer -> Tls.Config.server ->
    Reader.t -> Writer.t -> t Deferred.t

  (** [client_of_fd ?tracer client ~host fd] is [t], after client-side
      TLS handshake using [client] configuration and [host]. *)
  val create_client : ?trace:tracer -> Tls.Config.client -> ?host:string ->
    Reader.t -> Writer.t -> t Deferred.t

  (** [accept ?tracer server fd] is [t], after accepting a
      client on [fd] and upgrading to a TLS connection. *)
  val accept  : ?trace:tracer -> Tls.Config.server ->
    Reader.t -> Writer.t -> t Deferred.t

  (** [connect ?tracer client (host, port)] is [t], after successful
      connection to [host] on [port] and TLS upgrade. *)
  val connect : ?trace:tracer -> Tls.Config.client -> host:string ->
    Reader.t -> Writer.t -> t Deferred.t

  (** {2 Common stream operations} *)

  (** [read t buffer] is [length], the number of bytes read into
      [buffer]. *)
  val read   : t -> Cstruct.t      -> int  Deferred.t

  (** [write t buffer] writes the [buffer] to the session. *)
  val write  : t -> Cstruct.t      -> unit Deferred.t

  (** [writev t buffers] writes the [buffers] to the session. *)
  val writev : t -> Cstruct.t list -> unit Deferred.t

  (** [read_bytes t bytes offset len] is [read_bytes], the amount of
      bytes read. *)
  val read_bytes  : t -> Bigstring.t -> int -> int -> int  Deferred.t

  (** [write_bytes t bytes offset length] writes [length] bytes of
      [bytes] starting at [offset] to the session. *)
  val write_bytes : t -> Bigstring.t -> int -> int -> unit Deferred.t

  (** [close t] closes the TLS session by sending a close notify to the peer. *)
  val close_tls : t -> unit Deferred.t

  (** [close t] closes the TLS session and the underlying file descriptor. *)
  val close : t -> unit Deferred.t

  (** [reneg t] renegotiates the keys of the session. *)
  val reneg : t -> unit Deferred.t

  (** [epoch t] returns [epoch], which contains information of the
      active session. *)
  val epoch  : t -> [ `Ok of Tls.Types.epoch_data | `Error ]
end

(** {1 High-level API} *)

(** [accept_ext ?trace server fd] is [(ic, oc), sockaddr], the input
    and output channel from an accepted connection on the given [fd],
    after upgrading to TLS using the [server] configuration. *)
val accept_ext :
  ?trace:tracer -> Tls.Config.server -> Reader.t -> Writer.t ->
  (Reader.t * Writer.t) Deferred.t

(** [accept ?trace own_cert fd] is [(ic, oc), sockaddr], the input and
    output channel from the accepted connection on [fd], using the
    default configuration with the given [own_cert]. *)
val accept :
  ?trace:tracer -> Tls.Config.own_cert -> Reader.t -> Writer.t ->
  (Reader.t * Writer.t) Deferred.t

(** [connect_ext ?trace client (host, port)] is [ic, oc], the input
    and output channel of a TLS connection to [host] on [port] using
    the [client] configuration. *)
val connect_ext :
  ?trace:tracer -> Tls.Config.client -> host:string -> Reader.t -> Writer.t ->
  (Reader.t * Writer.t) Deferred.t

(** [connect ?trace authenticator (host, port)] is [ic, oc], the input
    and output channel of a TLS connection to [host] on [port] using the
    default configuration and the [authenticator]. *)
val connect :
  ?trace:tracer -> X509_async.authenticator -> host:string -> Reader.t -> Writer.t ->
  (Reader.t * Writer.t) Deferred.t

(** [of_t t] is [ic, oc], the input and output channel.  [close]
    defaults to [!Unix.close]. *)
val of_t : Unix.t -> (Reader.t * Writer.t) Deferred.t
