
type certificate
type stack = certificate * certificate list

val parse       : Cstruct.t -> certificate option
val parse_stack : Cstruct.t list -> stack option
val cs_of_cert  : certificate -> Cstruct.t
val asn_of_cert : certificate -> Asn_grammars.certificate

type certificate_failure =
  | InvalidCertificate
  | InvalidSignature
  | CertificateExpired
  | InvalidExtensions
  | InvalidPathlen
  | SelfSigned
  | NoTrustAnchor
  | InvalidInput
  | InvalidServerExtensions
  | InvalidServerName
  | InvalidCA

val verify_chain_of_trust :
  ?host:string -> time:int -> anchors:(certificate list) -> stack
  -> [ `Ok | `Fail of certificate_failure ]

val valid_cas : time:int -> certificate list -> certificate list

