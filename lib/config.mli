open Core

exception Invalid_configuration of string

type own_cert = Certificate.certificate * Nocrypto.RSA.priv

(* some config parameters *)
type config = private {
  (* ordered list (regarding preference) of supported cipher suites *)
  ciphers                 : Ciphersuite.ciphersuite list ;
  (* (max, min) *)
  protocol_versions       : tls_version * tls_version ;
  (* ordered list (regarding preference) *)
  hashes                  : Ciphersuite.hash_algorithm list ;
  (* signatures              : Packet.signature_algorithm_type list ; *)
  use_rekeying            : bool ;
  require_secure_rekeying : bool ;
  validator               : X509.Validator.t option ;
  peer_name               : string option ;
  own_certificate         : own_cert option ;
}

type rekeying = [ `No | `Yes | `Yes_require_secure ]

val supported_ciphers : Ciphersuite.ciphersuite list
val supported_hashes  : Ciphersuite.hash_algorithm list
val create : ?ciphers:     Ciphersuite.ciphersuite list    ->
             ?version:     tls_version * tls_version       ->
             ?hashes:      Ciphersuite.hash_algorithm list ->
             ?rekeying:    rekeying                        ->
             ?validator:   X509.Validator.t                ->
             ?peer_name:   string                          ->
             ?certificate: own_cert                        ->
             unit -> config
