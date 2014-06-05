open Core

exception Invalid_configuration of string

type own_cert = Certificate.certificate * Nocrypto.RSA.priv

type config = {
  ciphers                 : Ciphersuite.ciphersuite list ;
  protocol_versions       : tls_version * tls_version ;
  hashes                  : Ciphersuite.hash_algorithm list ;
  (* signatures              : Packet.signature_algorithm_type list ; *)
  use_rekeying            : bool ;
  require_secure_rekeying : bool ;
  validator               : X509.Validator.t option ;
  peer_name               : string option ;
  own_certificate         : own_cert option ;
}

let supported_hashes =
  Ciphersuite.([ SHA512 ; SHA384 ; SHA256 ; SHA ; MD5 ])

let supported_ciphers = Ciphersuite.([
    TLS_RSA_WITH_AES_256_CBC_SHA ;
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA ;
    TLS_RSA_WITH_AES_128_CBC_SHA ;
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA ;
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
    TLS_RSA_WITH_3DES_EDE_CBC_SHA ;
    TLS_RSA_WITH_RC4_128_SHA ;
    TLS_RSA_WITH_RC4_128_MD5
  ])


let default_config = {
  ciphers           = supported_ciphers ;
  protocol_versions = (TLS_1_2, TLS_1_0) ;
  hashes            = supported_hashes ;
  use_rekeying      = true ;
  require_secure_rekeying = true ;
  validator         = None ;
  peer_name         = None ;
  own_certificate   = None ;
}

let invalid msg = raise (Invalid_configuration msg)

let validate_common config =
  let (v_max, v_min) = config.protocol_versions in
  if v_max < v_min then invalid "bad version range" ;
  ( match config.hashes with
    | [] when v_max >= TLS_1_2 -> invalid "TLS 1.2 allowed but not hashes"
    | _                        -> () )

let validate_client config = ()

let validate_server config = ()
(*   config.ciphers |> List.iter (fun cip ->
    let open Ciphersuite in
    let kex = ciphersuite_kex cip in
    match (config.own_certificate, needs_certificate kex) with
    | (_, false)        -> ()
    | (None, true)      ->
        invalid "some allowed ciphers need cert when none given"
    | (Some cert, true) ->
        match (kex, cert_type cert) with
        |  *)


type client = config
type server = config

let of_server conf = conf
and of_client conf = conf

let peer conf name = { conf with peer_name = Some name }

let (<?>) ma b = match ma with None -> b | Some a -> a

let client_exn
  ?ciphers ?version ?hashes ?rekeying ?validator ?require_secure_rekeying () =
  let config =
    { default_config with
        ciphers           = ciphers  <?> default_config.ciphers ;
        protocol_versions = version  <?> default_config.protocol_versions ;
        hashes            = hashes   <?> default_config.hashes ;
        use_rekeying      = rekeying <?> default_config.use_rekeying ;
        validator         = validator ;
        require_secure_rekeying =
          require_secure_rekeying    <?> default_config.require_secure_rekeying ;
    } in
  ( validate_common config ; validate_client config ; config )

let server_exn
  ?ciphers ?version ?hashes ?rekeying ?certificate () =
  let config =
    { default_config with
        ciphers           = ciphers  <?> default_config.ciphers ;
        protocol_versions = version  <?> default_config.protocol_versions ;
        hashes            = hashes   <?> default_config.hashes ;
        use_rekeying      = rekeying <?> default_config.use_rekeying ;
        own_certificate   = certificate;
    } in
  ( validate_common config ; validate_server config ; config )
