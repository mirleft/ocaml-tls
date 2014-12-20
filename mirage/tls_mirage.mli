
module Make (FLOW : V1_LWT.FLOW) (E : V1_LWT.ENTROPY) : sig
  include Tls_mirage_types.TLS_core
end
  with module FLOW    := FLOW
   and module ENTROPY := E

module Make_flow (TCP : V1_LWT.TCPV4) (E : V1_LWT.ENTROPY) : sig
  include Tls_mirage_types.TLS_core
  include V1_LWT.TCPV4
    with type flow  := flow
     and type error := error
end
  with module TCP     := TCP
   and module ENTROPY := E

module X509 (KV : V1_LWT.KV_RO) (C : V1.CLOCK) : sig
  val authenticator : KV.t -> [< `Noop | `CAs ] -> X509.Authenticator.t Lwt.t
  val certificate   : KV.t -> [< `Default | `Name of string ]
                         -> (X509.Cert.t list * X509.PK.t) Lwt.t
end
