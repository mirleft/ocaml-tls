(** Effectful operations using Mirage for pure TLS. *)

open Result

(** TLS module given a flow *)
module Make (F : Mirage_flow_lwt.S) : sig

  module FLOW : Mirage_flow_lwt.S

  (** possible errors: incoming alert, processing failure, or a
      problem in the underlying flow. *)
  type error  = [ `Tls_alert   of Tls.Packet.alert_type
                | `Tls_failure of Tls.Engine.failure
                | `Read of F.error
                | `Write of F.write_error ]

  type write_error = [ `Closed | error ]
  (** The type for write errors. *)

  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  type tracer = Sexplib.Sexp.t -> unit

  (** we provide the FLOW interface *)
  include Mirage_flow_lwt.S
    with type 'a io  := 'a io
     and type buffer := buffer
     and type error := error
     and type write_error := write_error


  (** [reneg ~authenticator ~acceptable_cas ~cert ~drop t] renegotiates the
      session, and blocks until the renegotiation finished.  Optionally, a new
      [authenticator] and [acceptable_cas] can be used.  The own certificate can
      be adjusted by [cert]. If [drop] is [true] (the default),
      application data received before the renegotiation finished is dropped. *)
  val reneg : ?authenticator:X509.Authenticator.a ->
    ?acceptable_cas:X509.distinguished_name list -> ?cert:Tls.Config.own_cert ->
    ?drop:bool -> flow -> (unit, write_error) result Lwt.t

  (** [client_of_flow ~trace client ~host flow] upgrades the existing connection
      to TLS using the [client] configuration, using [host] as peer name. *)
  val client_of_flow :
    ?trace:tracer -> Tls.Config.client -> ?host:string -> FLOW.flow ->
    (flow, write_error) result Lwt.t

  (** [server_of_flow ?tracer server flow] upgrades the flow to a TLS
      connection using the [server] configuration. *)
  val server_of_flow :
    ?trace:tracer -> Tls.Config.server -> FLOW.flow ->
    (flow, write_error) result Lwt.t

  (** [epoch flow] extracts information of the established session. *)
  val epoch : flow -> (Tls.Core.epoch_data, unit) result

end
  with module FLOW = F


(** X.509 handling given a key value store and a clock *)
module X509 (KV : Mirage_kv_lwt.RO) (C : Mirage_clock.PCLOCK) : sig
  (** [authenticator store clock typ] creates an [authenticator], either
      using the given certificate authorities in the [store] or
      null. *)
  val authenticator : KV.t -> C.t -> [< `Noop | `CAs ] -> X509.Authenticator.a Lwt.t

  (** [certificate store typ] unmarshals a certificate chain and
      private key material from the [store]. *)
  val certificate   : KV.t -> [< `Default | `Name of string ]
                           -> (X509.t list * Nocrypto.Rsa.priv) Lwt.t
end
