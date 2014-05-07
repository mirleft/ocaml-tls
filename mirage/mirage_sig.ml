
module type DEVICE = sig
  (** Device operations.
      Defines the functions to connect and disconnect any device *)

  type +'a io
  (** A potentially blocking I/O operation *)

  type t
  (** The type representing the internal state of the device *)

  type error
  (** An error signalled by the device, normally returned after a
      connection attempt *)

  type id
  (** Type defining an identifier for this device that uniquely
      identifies it among a device tree. *)

  val id : t -> id
  (** Return the identifier that was used to construct this device *)

  val connect: id -> [ `Error of error | `Ok of t ] io
  (** Connect to the device identified by [id] *)

  val disconnect : t -> unit io
  (** Disconnect from the device.  While this might take some
      time to complete, it can never result in an error. *)
end

module type TCPV4 = sig
  (** A TCPv4 stack that can send and receive reliable streams using the TCP protocol. *)

  type buffer
  (** Abstract type for a memory buffer that may not be page aligned. *)

  type ipv4
  (** Abstract type for an IPv4 stack for this stack to connect to. *)

  type ipv4addr
  (** Abstract type for an IPv4 address representation. *)

  type ipv4input
  (** An input function continuation to pass onto the underlying {!ipv4}
      stack.  This will normally be a NOOP for a conventional kernel, but
      a direct implementation will parse the buffer. *)

  type flow
  (** A flow represents the state of a single TCPv4 stream that is connected
      to an endpoint. *)

  type error = [
    | `Unknown of string (** an undiagnosed error. *)
    | `Timeout  (** connection attempt did not get a valid response. *)
    | `Refused  (** connection attempt was actively refused via an RST. *)
  ]
  (** IO operation errors *)

  include DEVICE with
      type error := error
  and type id := ipv4

  type callback = flow -> unit io
  (** Application callback that receives a [flow] that it can read/write to. *)

  val get_dest : flow -> ipv4addr * int
  (** Get the destination IPv4 address and destination port that a flow is
      currently connected to. *)

  val read : flow -> [`Ok of buffer | `Eof | `Error of error ] io
  (** [read flow] will block until it either successfully reads a segment
      of data from the current flow, receives an [Eof] signifying that
      the connection is now closed, or an [Error]. *)

  val write : flow -> buffer -> unit io
  (** [write flow buffer] will block until the contents of [buffer] are
      transmitted to the remote endpoint.  The contents may be transmitted
      in separate packets, depending on the underlying transport. *)

  val writev : flow -> buffer list -> unit io
  (** [writev flow buffers] will block until the contents of [buffer list]
      are all successfully transmitted to the remote endpoint. *)

  val write_nodelay : flow -> buffer -> unit io
  (** [write_nodelay flow] will block until the contents of [buffer list]
      are all successfully transmitted to the remote endpoint. Buffering
      within the stack is minimized in this mode.  Note that this API will
      change in a future revision to be a per-flow attribute instead of a
      separately exposed function. *)

  val writev_nodelay : flow -> buffer list -> unit io
  (** [writev_nodelay flow] will block until the contents of [buffer list]
      are all successfully transmitted to the remote endpoint. Buffering
      within the stack is minimized in this mode.  Note that this API will
      change in a future revision to be a per-flow attribute instead of a
      separately exposed function. *)

  val close : flow -> unit io
  (** [close flow] will signal to the remote endpoint that the flow is now
      shutdown.  The caller should not perform any writes after this call. *)

  val create_connection : t -> ipv4addr * int ->
    [ `Ok of flow | `Error of error ] io
  (** [create_connection t (addr,port)] will open a TCPv4 connection to the
      specified endpoint. *)

  val input: t -> listeners:(int -> callback option) -> ipv4input
  (** [input t listeners] defines a mapping of threads that are willing to
      accept new flows on a given port.  If the [callback] returns [None],
      the input function will return an RST to refuse connections on a port. *)
end

