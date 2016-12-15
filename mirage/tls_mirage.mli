(** Effectful operations using Mirage for pure TLS. *)
open Result

(** TLS module given a flow *)
module Make (F : V1_LWT.FLOW) : sig
  module FLOW : V1_LWT.FLOW

  (** possible errors: incoming alert, processing failure, or a
      problem in the underlying flow. *)
  type error  = [ `Tls_alert   of Tls.Packet.alert_type
                | `Tls_failure of Tls.Engine.failure
                | `Msg of string
                | `Flow        of F.error ]

  type write_error = [ `Tls_alert   of Tls.Packet.alert_type
                     | `Tls_failure of Tls.Engine.failure
                     | `Closed
                     | `Msg of string
                     | `Flow        of F.write_error ]

  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  type tracer = Sexplib.Sexp.t -> unit

  (** we provide the FLOW interface *)
  include V1_LWT.FLOW
    with type 'a io  := 'a io
     and type error  := error
     and type write_error := write_error
     and type buffer := buffer

  (** [reneg flow] renegotiates the session. *)
  val reneg : flow -> (unit, write_error) result Lwt.t

  (** [client_of_flow ~trace client ~host flow] upgrades the existing connection
      to TLS using the [client] configuration, using [host] as peer name. *)
  val client_of_flow :
    ?trace:tracer -> Tls.Config.client -> ?host:string -> F.flow ->
    (flow, write_error) result Lwt.t

  (** [server_of_flow ?tracer server flow] upgrades the flow to a TLS
      connection using the [server] configuration. *)
  val server_of_flow :
    ?trace:tracer -> Tls.Config.server -> F.flow ->
    (flow, write_error) result Lwt.t

  (** [epoch flow] extracts information of the established session. *)
  val epoch : flow -> (Tls.Core.epoch_data, unit) result

end
  with module FLOW = F

(** X.509 handling given a key value store and a clock *)
module X509 (KV : V1_LWT.KV_RO) (C : V1.PCLOCK) : sig
  (** [authenticator store clock typ] creates an [authenticator], either
      using the given certificate authorities in the [store] or
      null. *)
  val authenticator : KV.t -> C.t -> [< `Noop | `CAs ] -> X509.Authenticator.a Lwt.t

  (** [certificate store typ] unmarshals a certificate chain and
      private key material from the [store]. *)
  val certificate   : KV.t -> [< `Default | `Name of string ]
                           -> (X509.t list * Nocrypto.Rsa.priv) Lwt.t
end
