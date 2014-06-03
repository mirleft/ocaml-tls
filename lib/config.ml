open Core

type own_cert = Certificate.certificate * Nocrypto.RSA.priv

(* some config parameters *)
type config = {
  ciphers                 : Ciphersuite.ciphersuite list ;
  protocol_versions       : tls_version list ;
  hashes                  : Ciphersuite.hash_algorithm list ;
  (* signatures              : Packet.signature_algorithm_type list ; *)
  use_rekeying            : bool ;
  require_secure_rekeying : bool ;
  validator               : X509.Validator.t option ;
  peer_name               : string option ;
  own_certificate         : own_cert option ;
}

let default_config = {
  (* ordered list (regarding preference) of supported cipher suites *)
  ciphers = Ciphersuite.([ TLS_RSA_WITH_AES_256_CBC_SHA ;
                           TLS_DHE_RSA_WITH_AES_256_CBC_SHA ;
                           TLS_RSA_WITH_AES_128_CBC_SHA ;
                           TLS_DHE_RSA_WITH_AES_128_CBC_SHA ;
                           TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
                           TLS_RSA_WITH_3DES_EDE_CBC_SHA ;
                           TLS_RSA_WITH_RC4_128_SHA ;
                           TLS_RSA_WITH_RC4_128_MD5 ]) ;
  (* ordered list of decreasing protocol versions *)
  protocol_versions = [ TLS_1_2 ; TLS_1_1 ; TLS_1_0 ] ;
  (* ordered list (regarding preference) *)
  hashes = Ciphersuite.([ SHA512 ; SHA384 ; SHA256 ; SHA ; MD5 ]) ;
  (* signatures = [ Packet.RSA ] *)
  (* whether or not to rekey *)
  use_rekeying = true ;
  require_secure_rekeying = true ;
  validator = None ;
  peer_name = None ;
  own_certificate = None ;
}

let max_protocol_version config = List.hd config.protocol_versions
let min_protocol_version config = Utils.last config.protocol_versions

(* find highest version between v and supported versions *)
let supported_protocol_version config v =
  (* implicitly assumes that sups is decreasing ordered and without any holes *)
  let max = max_protocol_version config in
  let min = min_protocol_version config in
  match v >= max, v >= min with
    | true, _    -> Some max
    | _   , true -> Some v
    | _   , _    -> None
