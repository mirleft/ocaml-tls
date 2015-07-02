(** Effectful operations usign mirage for pure TLS. *)

(** TLS module given a flow*)
module Make (F : V1_LWT.FLOW) : sig

  module FLOW    : V1_LWT.FLOW

  (** possible errors: incoming alert, processing failure, or a
      problem in the underlying flow. *)
  type error  = [ `Tls_alert   of Tls.Packet.alert_type
                | `Tls_failure of Tls.Engine.failure
                | `Flow        of FLOW.error ]
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  type tracer = Sexplib.Sexp.t -> unit

  (** we provide the FLOW interface *)
  include V1_LWT.FLOW
    with type error  := error
     and type 'a io  := 'a io
     and type buffer := buffer

  (** [reneg flow] renegotiates the session. *)
  val reneg  : flow -> [ `Ok of unit | `Eof | `Error of error ] Lwt.t

  (** [client_of_flow ?trace client hostname flow] upgrades the
      existing connection to TLS using the [client] configuration and
      given [hostname]. *)
  val client_of_flow :
    ?trace:tracer -> Tls.Config.client -> string -> FLOW.flow ->
    [> `Ok of flow | `Error of error | `Eof ] Lwt.t

  (** [server_of_flow ?tracer server flow] upgrades the flow to a TLS
      connection using the [server] configuration. *)
  val server_of_flow :
    ?trace:tracer -> Tls.Config.server -> FLOW.flow ->
    [> `Ok of flow | `Error of error | `Eof ] Lwt.t

  (** [epoch flow] extracts information of the established session. *)
  val epoch : flow -> [ `Ok of Tls.Core.epoch_data | `Error ]

end
  with module FLOW = F


(** X.509 handling given a key value store and a clock *)
module X509 (KV : V1_LWT.KV_RO) (C : V1.CLOCK) : sig
  (** [authenticator store typ] creates an [authenticator], either
      using the given certificate authorities in the [store] or
      null. *)
  val authenticator : KV.t -> [< `Noop | `CAs ] -> X509.Authenticator.a Lwt.t

  (** [certificate store typ] unmarshals a certificate chain and
      private key material from the [store]. *)
  val certificate   : KV.t -> [< `Default | `Name of string ]
                           -> (X509.t list * Nocrypto.Rsa.priv) Lwt.t
end
