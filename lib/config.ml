open Utils

open Core

exception Invalid_configuration of string

type own_cert = Certificate.certificate list * Nocrypto.RSA.priv

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

let min_dh_size = 512

let min_rsa_key_size = 1024

let default_config = {
  ciphers                 = supported_ciphers ;
  protocol_versions       = (TLS_1_2, TLS_1_0) ;
  hashes                  = supported_hashes ;
  use_rekeying            = true ;
  require_secure_rekeying = true ;
  validator               = None ;
  peer_name               = None ;
  own_certificate         = None ;
}

let invalid msg = raise (Invalid_configuration msg)

let validate_common config =
  let (v_max, v_min) = config.protocol_versions in
  if v_max < v_min then invalid "bad version range" ;
  ( match config.hashes with
    | [] when v_max >= TLS_1_2                          ->
       invalid "TLS 1.2 allowed but not hashes"
    | hs when not (List_set.subset hs supported_hashes) ->
       invalid "Some hash algorithms are not supported"
    | _                                                 ->
       () ) ;
  if not (List_set.subset config.ciphers supported_ciphers) then
    invalid "given ciphers are not supported" ;
  if not (List_set.is_proper_set config.ciphers) then
    invalid "set of ciphers is not a proper set" ;
  if List.exists Ciphersuite.null_cipher config.ciphers then
    invalid "some provided cipher offers a NULL method"

let validate_client config = ()

let validate_server config =
  let open Ciphersuite in
  List.map ciphersuite_kex config.ciphers |>
    List.filter needs_certificate |>
    List.iter (fun kex ->
      let ctype, cusage = match config.own_certificate with
        | None | Some ([], _) -> invalid "no certificate provided"
        | Some (c::_, _)      -> Certificate.(cert_type c, cert_usage c)
      in
      let ktype, usage = required_keytype_and_usage kex in
      if ktype != ctype then invalid "need a certificate of different keytype for selected ciphers" ;
      match cusage with
      | None    -> ()
      | Some us ->
         if not (List.mem usage us) then
           invalid "require a certificate with a different keyusage" ) ;
  ( match config.own_certificate with
    | Some (c::_, priv) ->
       let pub = Nocrypto.RSA.pub_of_priv priv in
       let open Asn_grammars in
       ( match Certificate.(asn_of_cert c).tbs_cert.pk_info with
         | PK.RSA pub' when pub = pub' -> ()
         | _                           -> invalid "public / private key combination" )
    | None | Some ([], _) -> () ) ;
  ( match config.own_certificate with
    | None         -> ()
    | Some (xs, _) ->
        match init_and_last xs with
        | None | Some ([], _) -> ()
        | Some (s::cs, ta)    ->
            match
              Certificate.verify_chain_of_trust ~anchors:[ta] (s, cs)
            with
            | `Ok     -> ()
            | `Fail x -> invalid ("certificate chain does not validate: " ^
                               (Certificate.certificate_failure_to_string x)) )
   (* TODO: verify that certificates are x509 v3 if TLS_1_2 *)

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
  ?ciphers ?version ?hashes ?rekeying ?certificate ?require_secure_rekeying () =
  let config =
    { default_config with
        ciphers           = ciphers  <?> default_config.ciphers ;
        protocol_versions = version  <?> default_config.protocol_versions ;
        hashes            = hashes   <?> default_config.hashes ;
        use_rekeying      = rekeying <?> default_config.use_rekeying ;
        own_certificate   = certificate;
        require_secure_rekeying =
          require_secure_rekeying    <?> default_config.require_secure_rekeying ;
    } in
  ( validate_common config ; validate_server config ; config )



(* Kinda stubby - rethink. *)

let config_of_sexp _ = failwith "can't parse config from sexp"

open Sexplib

let sexp_of_version =
  Conv.sexp_of_pair sexp_of_tls_version sexp_of_tls_version

let sexp_of_validator_o =
  Conv.sexp_of_option (fun _ -> Sexp.Atom "<VALIDATOR>")

let sexp_of_certificate_o =
  Conv.sexp_of_option (fun _ -> Sexp.Atom "<CERTIFICATE>")

let sexp_of_config c =
  let open Ciphersuite in
  Sexp_ext.record [
    "ciphers"        , Conv.sexp_of_list sexp_of_ciphersuite c.ciphers ;
    "version"        , sexp_of_version c.protocol_versions ;
    "hashes"         , Conv.sexp_of_list sexp_of_hash_algorithm c.hashes ;
    "use_rekeying"   , Conv.sexp_of_bool c.use_rekeying ;
    "requre_sec_rek" , Conv.sexp_of_bool c.require_secure_rekeying ;
    "validator"      , sexp_of_validator_o c.validator ;
    "peer_name"      , Conv.(sexp_of_option sexp_of_string) c.peer_name ;
    "certificate"    , sexp_of_certificate_o c.own_certificate ;
  ]
