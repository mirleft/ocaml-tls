open Nocrypto

open Utils
open Core

open Sexplib.Std


type certchain = Certificate.certificate list * Rsa.priv with sexp

type own_cert = [
  | `None
  | `Single of certchain
  | `Multiple of certchain list
  | `Multiple_default of certchain * certchain list
] with sexp

type config = {
  ciphers           : Ciphersuite.ciphersuite list ;
  protocol_versions : tls_version * tls_version ;
  hashes            : Hash.hash list ;
  (* signatures        : Packet.signature_algorithm_type list ; *)
  use_reneg         : bool ;
  secure_reneg      : bool ;
  authenticator     : X509.Authenticator.t option ;
  peer_name         : string option ;
  own_certificates  : own_cert ;
}

let config_of_sexp _ = invalid_arg "I'm afraid I cannot do this"
let sexp_of_config _ = Sexplib.Sexp.Atom "no config"

module Ciphers = struct

  open Ciphersuite

  (* A good place for various pre-baked cipher lists and helper functions to
   * slice and groom those lists. *)

  let default = [
    `TLS_DHE_RSA_WITH_AES_256_CCM ;
    `TLS_DHE_RSA_WITH_AES_128_CCM ;
    `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 ;
    `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 ;
    `TLS_DHE_RSA_WITH_AES_256_CBC_SHA ;
    `TLS_DHE_RSA_WITH_AES_128_CBC_SHA ;
    `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
    `TLS_RSA_WITH_AES_256_CCM ;
    `TLS_RSA_WITH_AES_128_CCM ;
    `TLS_RSA_WITH_AES_256_CBC_SHA256 ;
    `TLS_RSA_WITH_AES_128_CBC_SHA256 ;
    `TLS_RSA_WITH_AES_256_CBC_SHA ;
    `TLS_RSA_WITH_AES_128_CBC_SHA ;
    `TLS_RSA_WITH_3DES_EDE_CBC_SHA ;
    ]

  let supported = default @ [
    `TLS_RSA_WITH_RC4_128_SHA ;
    `TLS_RSA_WITH_RC4_128_MD5
    ]

  let pfs_of = List.filter Ciphersuite.ciphersuite_pfs

  let pfs = pfs_of default

end

let default_hashes =
  [ `SHA512 ; `SHA384 ; `SHA256 ; `SHA224 ; `SHA1 ]

let supported_hashes =
  default_hashes @ [ `MD5 ]

let min_dh_size = 512

let min_rsa_key_size = 1024

let default_config = {
  ciphers           = Ciphers.default ;
  protocol_versions = (TLS_1_0, TLS_1_2) ;
  hashes            = default_hashes ;
  use_reneg         = true ;
  secure_reneg      = true ;
  authenticator     = None ;
  peer_name         = None ;
  own_certificates  = `None ;
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
    invalid "set of ciphers is not a proper set" ;
  if List.length config.ciphers = 0 then
    invalid "set of ciphers is empty"

module CertTypeUsageOrdered = struct
  type t = Certificate.key_type * Asn_grammars.Extension.key_usage
  let compare = compare
end
module CertTypeUsageSet = Set.Make(CertTypeUsageOrdered)

let validate_certificate_chain = function
  | (s::chain, priv) ->
     let pub = Rsa.pub_of_priv priv in
     if Rsa.pub_bits pub < min_rsa_key_size then
       invalid "RSA key too short!" ;
     let open Asn_grammars in
     ( match Certificate.(asn_of_cert s).tbs_cert.pk_info with
       | PK.RSA pub' when pub = pub' ->
         ()
       | _                           ->
         invalid "public / private key combination" ) ;
     ( match init_and_last chain with
       | Some (ch, trust) ->
         (* TODO: verify that certificates are x509 v3 if TLS_1_2 *)
         ( match Certificate.verify_chain_of_trust ~anchors:[trust] (s :: ch) with
           | `Ok _   -> ()
           | `Fail x -> invalid ("certificate chain does not validate: " ^
                                 (Certificate.certificate_failure_to_string x)) )
       | None -> () )
  | _ -> invalid "certificate"

let validate_client config =
  match config.own_certificates with
  | `None -> ()
  | `Single c -> validate_certificate_chain c
  | _ -> invalid_arg "multiple client certificates not supported in client config"

module StringSet = Set.Make(String)

let non_overlapping cs =
  let namessets =
    let nameslists = filter_map cs ~f:(function
                                        | (s :: _, _) -> Some s
                                        | _           -> None)
                     |> List.map Certificate.cert_hostnames
    in
    List.map (fun xs -> List.fold_right StringSet.add xs StringSet.empty) nameslists
  in
  let rec check = function
    | []    -> ()
    | s::ss -> if not (List.for_all
                         (fun ss' -> StringSet.is_empty (StringSet.inter s ss'))
                         ss)
               then
                 invalid_arg "overlapping names in certificates"
               else
                 check ss
  in
  check namessets

let validate_server config =
  let open Ciphersuite in
  let typeusage =
    let tylist =
      List.map ciphersuite_kex config.ciphers |>
        List.filter needs_certificate |>
        List.map required_keytype_and_usage
    in
    List.fold_right CertTypeUsageSet.add tylist CertTypeUsageSet.empty
  and certificate_chains =
    match config.own_certificates with
    | `Single c                 -> [c]
    | `Multiple cs              -> cs
    | `Multiple_default (c, cs) -> c :: cs
    | `None                     -> []
  in
  let certtypes =
    filter_map ~f:(function
                    | (s::_, _) -> Some s
                    | _         -> None)
               certificate_chains |>
      List.map (fun c -> Certificate.(cert_type c, cert_usage c))
  in
  if
    not (CertTypeUsageSet.for_all
           (fun (t, u) ->
              List.exists (fun (ct, cu) ->
                  ct = t && option true (List.mem u) cu)
                certtypes)
           typeusage)
  then
    invalid "certificate type or usage does not match" ;
  List.iter validate_certificate_chain certificate_chains ;
  ( match config.own_certificates with
    | `Multiple cs              -> non_overlapping cs
    | `Multiple_default (_, cs) -> non_overlapping cs
    | _                         -> () )
  (* TODO: verify that certificates are x509 v3 if TLS_1_2 *)


type client = config with sexp
type server = config with sexp

let of_server conf = conf
and of_client conf = conf

let peer conf name = { conf with peer_name = Some name }

let (<?>) ma b = match ma with None -> b | Some a -> a

let client
  ~authenticator ?ciphers ?version ?hashes ?reneg ?certificates ?secure_reneg () =
  let config =
    { default_config with
        authenticator     = Some authenticator ;
        ciphers           = ciphers      <?> default_config.ciphers ;
        protocol_versions = version      <?> default_config.protocol_versions ;
        hashes            = hashes       <?> default_config.hashes ;
        use_reneg         = reneg        <?> default_config.use_reneg ;
        own_certificates  = certificates <?> default_config.own_certificates ;
        secure_reneg      = secure_reneg <?> default_config.secure_reneg ;
    } in
  ( validate_common config ; validate_client config ; config )

let server
  ?ciphers ?version ?hashes ?reneg ?certificates ?authenticator ?secure_reneg () =
  let config =
    { default_config with
        ciphers           = ciphers      <?> default_config.ciphers ;
        protocol_versions = version      <?> default_config.protocol_versions ;
        hashes            = hashes       <?> default_config.hashes ;
        use_reneg         = reneg        <?> default_config.use_reneg ;
        own_certificates  = certificates <?> default_config.own_certificates ;
        authenticator     = authenticator ;
        secure_reneg      = secure_reneg <?> default_config.secure_reneg ;
    } in
  ( validate_common config ; validate_server config ; config )

