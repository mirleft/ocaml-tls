(** Effectful operations using [Unix] for pure TLS. *)

(** possible errors: incoming alert, processing failure, or a
    problem in the underlying [Unix] flow. *)
type error =
  | Alert of Tls.Packet.alert_type
  | Failure of Tls.Engine.failure
  | Unix_error of Unix.error * string * string
  | Closed

val pp_error : Format.formatter -> error -> unit
(** Pretty-printer of {!val:error}. *)

type flow
(** The type of flows. *)

val read : flow -> ([ `Data of Cstruct.t | `Eof ], error) result
(** [read flow] blocks until some data is available and returns a
    fresh buffer containing it.

    If the remote endpoint calls [close] then calls to [read] will
    keep returning data until all the {i in-flight} data has been read.
    [read flow] will return [`Eof] when the remote endpoint has
    called [close] and when there is no more (i in-flight} data.
*)

val write : flow -> Cstruct.t -> (unit, error) result
(** [write flow buffer] writes a buffer to the TLS flow. There is no
    indication when the buffer has actually been read and, therefore,
    it must not be reused. The result [Ok ()] indicates success,
    [Error Closed] indicates that the connection is now closed and
    therefore the data could not be written. Other errors are possible.
*)

val writev : flow -> Cstruct.t list -> (unit, error) result
(** [writev flow bufs] is a successive call of {!val:write} with
    given [bufs]. *)

val close : flow -> unit
(** [close flow] sends a close notification to the peer and close the
    underlying [Unix] socket. *)

(** [reneg ~authenticator ~acceptable_cas ~cert ~drop t] renegotiates the
    session, and blocks until the renegotiation finished.  Optionally, a new
    [authenticator] and [acceptable_cas] can be used.  The own certificate can
    be adjusted by [cert]. If [drop] is [true] (the default),
    application data received before the renegotiation finished is dropped. *)
val reneg : ?authenticator:X509.Authenticator.t ->
  ?acceptable_cas:X509.Distinguished_name.t list -> ?cert:Tls.Config.own_cert ->
  ?drop:bool -> flow -> (unit, error) result

(** [key_update ~request t] updates the traffic key and requests a traffic key
    update from the peer if [request] is provided and [true] (the default).
    This is only supported in TLS 1.3. *)
val key_update : ?request:bool -> flow -> (unit, error) result

(** [client_of_flow client ~host socket] upgrades the existing connection
    to TLS using [client] configuration, using [host] as peer name. *)
val client_of_flow : Tls.Config.client -> ?host:[ `host ] Domain_name.t ->
  Unix.file_descr -> (flow, error) result

(** [server_of_flow server flow] upgrades the flow to a TLS
    connection using the [server] configuration. *)
val server_of_flow : Tls.Config.server -> Unix.file_descr ->
  (flow, error) result