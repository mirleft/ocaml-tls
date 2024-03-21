(** Effectful operations using Mirage for pure TLS. *)

(** TLS module given a flow *)
module Make (F : Mirage_flow.S) : sig

  (** possible errors: incoming alert, processing failure, or a
      problem in the underlying flow. *)
  type error  = [ `Tls_alert   of Tls.Packet.alert_type
                | `Tls_failure of Tls.Engine.failure
                | `Read of F.error
                | `Write of F.write_error ]

  type write_error = [ `Closed | error ]
  (** The type for write errors. *)

  (** we provide the FLOW interface *)
  include Mirage_flow.S
    with type error := error
     and type write_error := write_error

  (** [underlying t] returns the underlying flow. This is useful to extract
      information such as [src] and [dst] of that flow. *)
  val underlying : flow -> F.flow

  (** [reneg ~authenticator ~acceptable_cas ~cert ~drop t] renegotiates the
      session, and blocks until the renegotiation finished.  Optionally, a new
      [authenticator] and [acceptable_cas] can be used.  The own certificate can
      be adjusted by [cert]. If [drop] is [true] (the default),
      application data received before the renegotiation finished is dropped. *)
  val reneg : ?authenticator:X509.Authenticator.t ->
    ?acceptable_cas:X509.Distinguished_name.t list -> ?cert:Tls.Config.own_cert ->
    ?drop:bool -> flow -> (unit, [ write_error | `Msg of string ]) result Lwt.t

  (** [key_update ~request t] updates the traffic key and requests a traffic key
      update from the peer if [request] is provided and [true] (the default).
      This is only supported in TLS 1.3. *)
  val key_update : ?request:bool -> flow -> (unit, [ write_error | `Msg of string ]) result Lwt.t

  (** [client_of_flow client ~host flow] upgrades the existing connection
      to TLS using the [client] configuration, using [host] as peer name. *)
  val client_of_flow : Tls.Config.client -> ?host:[ `host ] Domain_name.t ->
     F.flow -> (flow, write_error) result Lwt.t

  (** [server_of_flow server flow] upgrades the flow to a TLS
      connection using the [server] configuration. *)
  val server_of_flow : Tls.Config.server -> F.flow ->
    (flow, write_error) result Lwt.t

  (** [epoch flow] extracts information of the established session. *)
  val epoch : flow -> (Tls.Core.epoch_data, unit) result

end

(** X.509 handling given a key value store and a clock *)
module X509 (KV : Mirage_kv.RO) (C : Mirage_clock.PCLOCK) : sig
  (** [authenticator ~allowed_hashes ~crl store] creates an [authenticator],
      using the given certificate authorities in the [store] as
      value for key "ca_roots.crt". If [allowed_hashes] is provided,
      only these hash algorithms are allowed for signatures of the certificate chain.
      If [crl] is provided, the corresponding file is read and used as
      revocation list (DER encoded). Both options only apply if [`CAs] is used.
 *)
  val authenticator : ?allowed_hashes:Mirage_crypto.Hash.hash list -> ?crl:string ->
    KV.t -> X509.Authenticator.t Lwt.t

  (** [certificate store typ] unmarshals a certificate chain and
      private key material from the [store]. *)
  val certificate   : KV.t -> [< `Default | `Name of string ]
    -> Tls.Config.certchain Lwt.t
end
