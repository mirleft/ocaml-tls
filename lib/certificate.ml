open Registry
open Asn_grammars
open Asn
open Utils

open Nocrypto


(*
 * There are two reasons to carry Cstruct.t around:
 * - we still need to hack on the cstruct to get bytes to hash
 *   ( this needs to go )
 * - we need a cs to send to the peer
 * It's a bit ugly to have two levels, and both are better solved by extending
 * the asn parser and writer respectively, but until then there needs to be one
 * place that hides the existence of this pair.
 *)

type certificate = {
  asn : Asn_grammars.certificate ;
  raw : Cstruct.t
}

let cs_of_cert  { raw ; _ } = raw
let asn_of_cert { asn ; _ } = asn

type stack = certificate * certificate list

type host = [ `Strict of string | `Wildcard of string ]

let parse cs =
  match Asn_grammars.certificate_of_cstruct cs with
  | None     -> None
  | Some asn -> Some { asn ; raw = cs }

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

(* partial: does not deal with other public key types *)
let cert_type { asn = cert } =
  match cert.tbs_cert.pk_info with
  | PK.RSA _    -> `RSA

let usage_export = Extension.(function
  | Digital_signature  -> `DigitalSignature
  | Content_commitment -> `ContentCommitment
  | Key_encipherment   -> `KeyEncipherment
  | Data_encipherment  -> `DataEncipherment
  | Key_agreement      -> `KeyAgreement
  | Key_cert_sign      -> `KeyCertSign
  | CRL_sign           -> `CRLSign
  | Encipher_only      -> `EncipherOnly
  | Decipher_only      -> `DeciperOnly )

let cert_usage { asn = cert } =
  match extn_key_usage cert with
  | Some (_, Extension.Key_usage usages) -> Some (List.map usage_export usages)
  | _                                    -> None

(* partial: does not deal with 'Other of OID.t' *)
let extended_usage_export = Extension.(function
  | Any              -> `Any
  | Server_auth      -> `ServerAuth
  | Client_auth      -> `ClientAuth
  | Code_signing     -> `CodeSigning
  | Email_protection -> `EmailProtection
  | Ipsec_end        -> `IPSecEnd
  | Ipsec_tunnel     -> `IPSecTunnel
  | Ipsec_user       -> `IPSecUser
  | Time_stamping    -> `TimeStamping
  | Ocsp_signing     -> `OCSPSigning )

let cert_extended_usage { asn = cert } =
  match extn_ext_key_usage cert with
  | Some (_, Extension.Ext_key_usage usages) -> Some (List.map extended_usage_export usages)
  | _                                        -> None

module Or_error =
  Control.Or_error_make ( struct type err = certificate_failure end )

open Or_error

let success = return ()

let lower = function
  | Ok _      -> `Ok
  | Error err -> `Fail err

(* TODO RFC 5280: A certificate MUST NOT include more than
                  one instance of a particular extension. *)

let issuer_matches_subject { asn = parent } { asn = cert } =
  Name.equal parent.tbs_cert.subject cert.tbs_cert.issuer

let is_self_signed cert = issuer_matches_subject cert cert
(* let is_self_signed { tbs_cert = { subject } } =
  Name.equal subject subject *)

let subject cert =
  map_find cert.tbs_cert.subject
           ~f:(function Name.CN n -> Some n | _ -> None)

let common_name_to_string cert =
  match subject cert with
  | None   -> "NO commonName:" ^ Utils.hexdump_to_str cert.signature_val
  | Some x -> x

let cert_hostnames { asn = cert } =
  let open Extension in
  match extn_subject_alt_name cert with
  | Some (_, Subject_alt_name names) ->
     filter_map names ~f:(function General_name.DNS x -> Some x | _ -> None)
  | _ ->
     match subject cert with
     | None   -> []
     | Some x -> [x]

(* XXX should return the tbs_cert blob from the parser, this is insane *)
let raw_cert_hack { asn ; raw } =
  let siglen = Cstruct.len asn.signature_val in
  let off    = if siglen > 128 then 1 else 0 in
  Cstruct.(sub raw 4 (len raw - (siglen + 4 + 19 + off)))

let validate_signature { asn = trusted } cert =
  let module A  = Algorithm in
  let module Cs = Ciphersuite in

  let tbs_raw = raw_cert_hack cert in
  match trusted.tbs_cert.pk_info with

  | PK.RSA issuing_key ->

     ( match Crypto.verifyRSA_and_unpadPKCS1 issuing_key cert.asn.signature_val with
       | Some signature ->
          ( match Crypto.pkcs1_digest_info_of_cstruct signature with
            | None              -> false
            | Some (algo, hash) ->
                let matches =
                  Crypto.hash_eq algo ~target:hash tbs_raw in
                (* XXX make something that extracts just the hash part of an asn
                 * algorithm as a ciphersuite hash, then simply check equality
                 * instead of this. *)
                match (cert.asn.signature_algo, algo) with
                | (A.MD5_RSA   , Cs.MD5)    -> matches
                | (A.SHA1_RSA  , Cs.SHA)    -> matches
                | (A.SHA256_RSA, Cs.SHA256) -> matches
                | (A.SHA384_RSA, Cs.SHA384) -> matches
                | _                         -> false )
       | None -> false )

  | _ -> false

let validate_time now cert =
(*   let from, till = cert.validity in *)
(* TODO:  from < now && now < till *)
  true

let validate_path_len pathlen { asn = cert } =
  (* X509 V1/V2 certificates do not contain X509v3 extensions! *)
  (* thus, we cannot check the path length. this will only ever happen for trust anchors: *)
  (* intermediate CAs are checked by is_cert_valid, which checks that the CA extensions are there *)
  (* whereas trust anchor are ok with getting V1/2 certificates *)
  (* TODO: make it configurable whether to accept V1/2 certificates at all *)
  let open Extension in
  match cert.tbs_cert.version, extn_basic_constr cert with
  | `V1, _                                           -> true
  | `V2, _                                           -> true
  | `V3, Some (_ , Basic_constraints (true, None))   -> true
  | `V3, Some (_ , Basic_constraints (true, Some n)) -> n >= pathlen
  | `V3, _                                           -> false

let validate_ca_extensions { asn = cert } =
  let open Extension in
  (* comments from RFC5280 *)
  (* 4.2.1.9 Basic Constraints *)
  (* Conforming CAs MUST include this extension in all CA certificates used *)
  (* to validate digital signatures on certificates and MUST mark the *)
  (* extension as critical in such certificates *)
  (* unfortunately, there are 8 CA certs (including the one which
      signed google.com) which are _NOT_ marked as critical *)
  ( match extn_basic_constr cert with
    | Some (_ , Basic_constraints (true, _))   -> true
    | _                                        -> false ) &&

  (* 4.2.1.3 Key Usage *)
  (* Conforming CAs MUST include key usage extension *)
  (* CA Cert (cacert.org) does not *)
  ( match extn_key_usage cert with
    (* When present, conforming CAs SHOULD mark this extension as critical *)
    (* yeah, you wish... *)
    | Some (crit, Key_usage usage) -> List.mem Key_cert_sign usage
    | _                            -> false ) &&

  (* Name Constraints - name constraints should match servername *)

  (* check criticality *)
  List.for_all (function
      | (true, Key_usage _)         -> true
      | (true, Basic_constraints _) -> true
      | (crit, _)                   -> not crit )
    cert.tbs_cert.extensions

let validate_server_extensions { asn = cert } =
  let open Extension in
  List.for_all (function
      | (_, Basic_constraints (true, _))  -> false
      | (_, Basic_constraints (false, _)) -> true
      | (_, Key_usage _)                  -> true
      | (_, Ext_key_usage _)              -> true
      | (_, Subject_alt_name _)           -> true
      | (c, Policies ps)                  -> not c || List.mem `Any ps
      (* we've to deal with _all_ extensions marked critical! *)
      | (crit, _)                         -> not crit )
    cert.tbs_cert.extensions


let is_cert_valid now cert =
    Printf.printf "verify intermediate certificate %s\n"
                  (common_name_to_string cert.asn);
    match
      validate_time now cert,
      validate_ca_extensions cert
    with
    | (true, true) -> success
    | (false, _)   -> fail CertificateExpired
    | (_, false)   -> fail InvalidExtensions

let has_valid_extensions cert =
  match cert.asn.tbs_cert.version, validate_ca_extensions cert with
  | `V1, _ -> true
  | `V2, _ -> true
  | `V3, x -> x

let is_ca_cert_valid now cert =
  match
    is_self_signed cert,
    validate_signature cert cert,
    validate_time now cert,
    has_valid_extensions cert
  with
  | (true, true, true, true) -> success
  | (false, _, _, _)         -> fail InvalidCA
  | (_, false, _, _)         -> fail InvalidSignature
  | (_, _, false, _)         -> fail CertificateExpired
  | (_, _, _, false)         -> fail InvalidExtensions

let validate_public_key_type { asn = cert } = function
  | None   -> true
  | Some x -> match x, cert.tbs_cert.pk_info with
              | `RSA , PK.RSA _ -> true
              | _    , _        -> false

let hostname_matches_wildcard should given =
  let open String in
  try
    match sub given 0 2, sub given 2 (length given - 2) with
    | "*.", dn when dn = should -> true
    | _   , _                   -> false
  with _ -> false

let validate_hostname cert host =
  let names = cert_hostnames cert in
  match host with
  | None                  -> true
  | Some (`Strict name)   -> List.mem name names
  | Some (`Wildcard name) ->
     List.mem name names ||
       try
         let idx = String.index name '.' + 1 in (* might throw *)
         let rt = String.sub name idx (String.length name - idx) in
         List.exists (hostname_matches_wildcard rt) names
       with _ -> false

let is_server_cert_valid ?host now cert =
  Printf.printf "verify server certificate %s\n"
                (common_name_to_string cert.asn);
  match
    validate_time now cert,
    validate_hostname cert host,
    validate_server_extensions cert
  with
  | (true, true, true) -> success
  | (false, _, _)      -> fail CertificateExpired
  | (_, false, _)      -> fail InvalidServerName
  | (_, _, false)      -> fail InvalidServerExtensions


let ext_authority_matches_subject trusted cert =
  let open Extension in
  match
    extn_authority_key_id cert.asn, extn_subject_key_id trusted.asn
  with
  | Some (_, Authority_key_id (Some auth, _, _)),
    Some (_, Subject_key_id au)                -> Cs.equal auth au
  (* TODO: check exact rules in RFC5280 *)
  | Some (_, Authority_key_id (None, _, _)), _ -> true (* not mandatory *)
  | None, _                                    -> true (* not mandatory *)
  | _, _                                       -> false

let signs pathlen trusted cert =
  Printf.printf "verifying relation of %s -> %s (pathlen %d)\n"
                (common_name_to_string trusted.asn)
                (common_name_to_string cert.asn)
                pathlen;
  match
    issuer_matches_subject trusted cert,
    ext_authority_matches_subject trusted cert,
    validate_signature trusted cert,
    validate_path_len pathlen trusted
  with
  | (true, true, true, true) -> success
  | (false, _, _, _)         -> fail InvalidCertificate
  | (_, false, _, _)         -> fail InvalidExtensions
  | (_, _, false, _)         -> fail InvalidSignature
  | (_, _, _, false)         -> fail InvalidPathlen


let find_issuer trusted cert =
  (* first have to find issuer of ``c`` in ``trusted`` *)
  Printf.printf "looking for issuer of %s (%d CAs)\n"
                (common_name_to_string cert.asn)
                (List.length trusted);
  List.filter (fun p -> issuer_matches_subject p cert) trusted

let parse_stack css =
  let rec loop certs = function
    | [] ->
      ( match List.rev certs with
        | []              -> None
        | server :: certs -> Some (server, certs ) )
    | cs :: css ->
        match parse cs with
        | None      -> None
        | Some cert -> loop (cert :: certs) css in
  loop [] css

let rec validate_anchors pathlen cert = function
  | []    -> fail NoTrustAnchor
  | x::xs -> match signs pathlen x cert with
             | Ok _    -> success
             | Error _ -> validate_anchors pathlen cert xs

let verify_chain_of_trust ?host ~time ~anchors (server, certs) =
  let res =
    let rec climb pathlen cert = function
      | super :: certs ->
          signs pathlen super cert >>= fun () ->
          climb (succ pathlen) super certs
      | [] ->
          match List.filter (validate_time time) (find_issuer anchors cert) with
          | [] when is_self_signed cert -> fail SelfSigned
          | []                          -> fail NoTrustAnchor
          | anchors                     ->
             validate_anchors pathlen cert anchors
    in
    is_server_cert_valid ?host time server >>= fun () ->
    mapM_ (is_cert_valid time) certs       >>= fun () ->
    climb 0 server certs
  in
  lower res

let valid_cas ~time cas =
  List.filter
    (fun cert -> is_success @@ is_ca_cert_valid time cert)
    cas

(* RFC5246 says 'root certificate authority MAY be omitted' *)

(* TODO: how to deal with
    2.16.840.1.113730.1.1 - Netscape certificate type
    2.16.840.1.113730.1.12 - SSL server name
    2.16.840.1.113730.1.13 - Netscape certificate comment *)

(* stuff from 4366 (TLS extensions):
  - root CAs
  - client cert url *)

(* Future TODO Certificate Revocation Lists and OCSP (RFC6520)
2.16.840.1.113730.1.2 - Base URL
2.16.840.1.113730.1.3 - Revocation URL
2.16.840.1.113730.1.4 - CA Revocation URL
2.16.840.1.113730.1.7 - Renewal URL
2.16.840.1.113730.1.8 - Netscape CA policy URL

2.5.4.38 - id-at-authorityRevocationList
2.5.4.39 - id-at-certificateRevocationList

2.5.29.20 - CRL Number
2.5.29.21 - reason code
2.5.29.27 - Delta CRL indicator
2.5.29.28 - Issuing Distribution Point
2.5.29.31 - CRL Distribution Points
2.5.29.46 - FreshestCRL

do not forget about 'authority information access' (private internet extension -- 4.2.2 of 5280) *)

(* Future TODO: Policies
2.5.29.32 - Certificate Policies
2.5.29.33 - Policy Mappings
2.5.29.36 - Policy Constraints
 *)

(* Future TODO: anything with subject_id and issuer_id ? seems to be not used by anybody *)

(* - test setup (ACM CCS'12):
            self-signed cert with requested commonName,
            self-signed cert with other commonName,
            valid signed cert with other commonName
   - also of interest: international domain names, wildcards *)

(* alternative approach: interface and implementation for certificate pinning *)
(* alternative approach': notary system / perspectives *)
(* alternative approach'': static list of trusted certificates *)
