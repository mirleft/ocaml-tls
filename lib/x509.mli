
module Pem : sig
  val parse : Cstruct.t -> (string * Cstruct.t) list
end

module Cert : sig
  type t = Certificate.certificate
  val of_pem_cstruct  : Cstruct.t -> t list
  val of_pem_cstruct1 : Cstruct.t -> t
end

module PK : sig
  type t = Nocrypto.Rsa.priv
  val of_pem_cstruct  : Cstruct.t -> t list
  val of_pem_cstruct1 : Cstruct.t -> t
end

module Validator : sig

  type validation = [ `Ok | `Fail of Certificate.certificate_failure ]
  type t

  val validate : t -> ?host:string -> Certificate.stack -> validation

  val chain_of_trust : time:int -> Cert.t list -> t
  val null : t
end
