
module Make_core (TCP : V1_LWT.TCPV4) : Tls_types.TLS_core
module Make_flow (TCP : V1_LWT.TCPV4) : V1_LWT.TCPV4

module X509 (KV : V1_LWT.KV_RO) (CL : V1.CLOCK) : sig
  open Tls.X509
  val validator   : KV.t -> [< `Noop | `CAs ] -> Validator.t Lwt.t
  val certificate : KV.t -> [< `Default | `Name of string ] -> (Cert.t * PK.t) Lwt.t
end
