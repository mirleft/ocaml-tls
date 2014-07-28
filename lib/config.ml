open Utils

open Core

type own_cert = Certificate.certificate list * Nocrypto.RSA.priv

type config = {
  ciphers           : Ciphersuite.ciphersuite list ;
  protocol_versions : tls_version * tls_version ;
  hashes            : Packet.hash_algorithm list ;
  (* signatures        : Packet.signature_algorithm_type list ; *)
  use_reneg         : bool ;
  secure_reneg      : bool ;
  authenticator     : X509.Authenticator.t option ;
  peer_name         : string option ;
  own_certificate   : own_cert option ;
}

module Ciphers = struct

  open Ciphersuite

  (* A good place for various pre-baked cipher lists and helper functions to
   * slice and groom those lists. *)

  let supported = [
    `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 ;
    `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 ;
    `TLS_DHE_RSA_WITH_AES_256_CBC_SHA ;
    `TLS_DHE_RSA_WITH_AES_128_CBC_SHA ;
    `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
    `TLS_RSA_WITH_AES_256_CBC_SHA256 ;
    `TLS_RSA_WITH_AES_128_CBC_SHA256 ;
    `TLS_RSA_WITH_AES_256_CBC_SHA ;
    `TLS_RSA_WITH_AES_128_CBC_SHA ;
    `TLS_RSA_WITH_3DES_EDE_CBC_SHA ;
    `TLS_RSA_WITH_RC4_128_SHA ;
    `TLS_RSA_WITH_RC4_128_MD5
    ]

  let pfs_of = List.filter Ciphersuite.ciphersuite_pfs

  let pfs = pfs_of supported

end

let supported_hashes =
  Packet.([ SHA512 ; SHA384 ; SHA256 ; SHA ; MD5 ])

let min_dh_size = 512

let min_rsa_key_size = 1024

let default_config = {
  ciphers           = Ciphers.pfs ;
  protocol_versions = (TLS_1_0, TLS_1_2) ;
  hashes            = supported_hashes ;
  use_reneg         = true ;
  secure_reneg      = true ;
  authenticator     = None ;
  peer_name         = None ;
  own_certificate   = None ;
}

let invalid msg = invalid_arg ("Tls.Config: invalid configuration: " ^ msg)

let validate_common config =
  let (v_min, v_max) = config.protocol_versions in
  if v_max < v_min then invalid "bad version range" ;
  ( match config.hashes with
    | [] when v_max >= TLS_1_2                          ->
       invalid "TLS 1.2 configured but no hashes provided"
    | hs when not (List_set.subset hs supported_hashes) ->
       invalid "Some hash algorithms are not supported"
    | _                                                 ->
       () ) ;
  if not (List_set.is_proper_set config.ciphers) then
    invalid "set of ciphers is not a proper set"

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

let client
  ?ciphers ?version ?hashes ?reneg ?authenticator ?secure_reneg () =
  let config =
    { default_config with
        ciphers           = ciphers      <?> default_config.ciphers ;
        protocol_versions = version      <?> default_config.protocol_versions ;
        hashes            = hashes       <?> default_config.hashes ;
        use_reneg         = reneg        <?> default_config.use_reneg ;
        authenticator     = authenticator ;
        secure_reneg      = secure_reneg <?> default_config.secure_reneg ;
    } in
  ( validate_common config ; validate_client config ; config )

let server
  ?ciphers ?version ?hashes ?reneg ?certificate ?secure_reneg () =
  let config =
    { default_config with
        ciphers           = ciphers      <?> default_config.ciphers ;
        protocol_versions = version      <?> default_config.protocol_versions ;
        hashes            = hashes       <?> default_config.hashes ;
        use_reneg         = reneg        <?> default_config.use_reneg ;
        own_certificate   = certificate;
        secure_reneg      = secure_reneg <?> default_config.secure_reneg ;
    } in
  ( validate_common config ; validate_server config ; config )


(* Kinda stubby - rethink. *)

let config_of_sexp _ = failwith "can't parse config from sexp"

open Sexplib

let sexp_of_version =
  Conv.sexp_of_pair sexp_of_tls_version sexp_of_tls_version

let sexp_of_authenticator_o =
  Conv.sexp_of_option (fun _ -> Sexp.Atom "<AUTHENTICATOR>")

let sexp_of_certificate_o =
  Conv.sexp_of_option (fun _ -> Sexp.Atom "<CERTIFICATE>")

let sexp_of_config c =
  let open Ciphersuite in
  Sexp_ext.record [
    "ciphers"        , Conv.sexp_of_list sexp_of_ciphersuite c.ciphers ;
    "version"        , sexp_of_version c.protocol_versions ;
    "hashes"         , Conv.sexp_of_list Packet.sexp_of_hash_algorithm c.hashes ;
    "use_reneg"      , Conv.sexp_of_bool c.use_reneg ;
    "secure_reneg"   , Conv.sexp_of_bool c.secure_reneg ;
    "authenticator"  , sexp_of_authenticator_o c.authenticator ;
    "peer_name"      , Conv.(sexp_of_option sexp_of_string) c.peer_name ;
    "certificate"    , sexp_of_certificate_o c.own_certificate ;
  ]
