
type certificate
type stack = certificate * certificate list

type host = [ `Strict of string | `Wildcard of string ]

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

type key_type = [ `RSA | `DH | `ECDH | `ECDSA ]

type key_usage = [
  | `DigitalSignature
  | `ContentCommitment
  | `KeyEncipherment
  | `DataEncipherment
  | `KeyAgreement
  | `KeyCertSign
  | `CRLSign
  | `EncipherOnly
  | `DeciperOnly
]

type extended_key_usage = [
  | `Any
  | `ServerAuth
  | `ClientAuth
  | `CodeSigning
  | `EmailProtection
  | `IPSecEnd
  | `IPSecTunnel
  | `IPSecUser
  | `TimeStamping
  | `OCSPSigning
]

val cert_type           : certificate -> key_type
val cert_usage          : certificate -> key_usage list option
val cert_extended_usage : certificate -> extended_key_usage list option

val verify_chain_of_trust :
  ?host:host -> time:int -> anchors:(certificate list) -> stack
  -> [ `Ok | `Fail of certificate_failure ]

val valid_cas : time:int -> certificate list -> certificate list

