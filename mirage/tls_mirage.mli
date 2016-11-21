(** Effectful operations using Mirage for pure TLS. *)

(** TLS module given a flow *)
module Make (F : V1_LWT.FLOW) : sig

  module FLOW : V1_LWT.FLOW

  (** possible errors: incoming alert, processing failure, or a
      problem in the underlying flow. *)
  type error  = [ `Tls_alert   of Tls.Packet.alert_type
                | `Tls_failure of Tls.Engine.failure
                | `Flow        of [ `Read of V1.Flow.error
                                  | `Write of V1.Flow.write_error ] ]
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  type tracer = Sexplib.Sexp.t -> unit

  (** we provide the FLOW interface *)
  include V1_LWT.FLOW
    with type 'a io  := 'a io
     and type buffer := buffer

  (** [reneg flow] renegotiates the session. *)
  val reneg : flow -> (unit, V1.Flow.write_error) result Lwt.t

  (** [client_of_flow ~trace client ~host flow] upgrades the existing connection
      to TLS using the [client] configuration, using [host] as peer name. *)
  val client_of_flow :
    ?trace:tracer -> Tls.Config.client -> ?host:string -> FLOW.flow ->
    (flow, V1.Flow.write_error) Result.result Lwt.t

  (** [server_of_flow ?tracer server flow] upgrades the flow to a TLS
      connection using the [server] configuration. *)
  val server_of_flow :
    ?trace:tracer -> Tls.Config.server -> FLOW.flow ->
    (flow, V1.Flow.write_error) Result.result Lwt.t

  (** [epoch flow] extracts information of the established session. *)
  val epoch : flow -> (Tls.Core.epoch_data, unit) Result.result

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
