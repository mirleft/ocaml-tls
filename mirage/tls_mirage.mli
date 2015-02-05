
module Make (F : V1_LWT.FLOW) (E : V1_LWT.ENTROPY) : sig

  module FLOW    : V1_LWT.FLOW
  module ENTROPY : V1_LWT.ENTROPY

  type error  = [
    | `Tls of string
    | `Tls_failure of Tls.Engine.failure
    | `Tls_alert of Tls.Packet.alert_type
    | `Flow of FLOW.error
  ]
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

  type tracer = Sexplib.Sexp.t -> unit

  include V1_LWT.FLOW
    with type error  := error
     and type 'a io  := 'a io
     and type buffer := buffer

  val attach_entropy : ENTROPY.t -> unit Lwt.t

  val reneg  : flow -> [ `Ok of unit | `Eof | `Error of error ] Lwt.t

  val client_of_flow :
    ?trace:tracer -> Tls.Config.client -> string -> FLOW.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t

  val server_of_flow :
    ?trace:tracer -> Tls.Config.server -> FLOW.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t

  val epoch : flow -> [ `Ok of Tls.Engine.epoch_data | `Error ]

end
  with module FLOW    = F
   and module ENTROPY = E


module X509 (KV : V1_LWT.KV_RO) (C : V1.CLOCK) : sig
  val authenticator : KV.t -> [< `Noop | `CAs ] -> X509.Authenticator.t Lwt.t
  val certificate   : KV.t -> [< `Default | `Name of string ]
                         -> (X509.Cert.t list * X509.PK.t) Lwt.t
end
