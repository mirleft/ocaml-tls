
module Make (TCP : V1_LWT.TCPV4) : sig
  include Tls_mirage_types.TLS_core
end with module TCP := TCP

module Make_flow (TCP : V1_LWT.TCPV4) : sig
  include Tls_mirage_types.TLS_core
  include V1_LWT.TCPV4
    with type flow  := flow
     and type error := error
end with module TCP := TCP

(* XXX CLOCK *)
module X509 (KV : V1_LWT.KV_RO) : sig
  open Tls.X509
  val validator   : KV.t -> [< `Noop | `CAs ] -> Validator.t Lwt.t
  val certificate : KV.t -> [< `Default | `Name of string ] -> (Cert.t * PK.t) Lwt.t
end
