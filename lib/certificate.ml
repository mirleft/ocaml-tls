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

let hostname_matches { asn = cert } name =
  let open Extension in
  match extn_subject_alt_name cert with
  | Some (_, Subject_alt_name names) ->
      List.exists
        (function General_name.DNS x -> x = name | _ -> false)
        names
  | _ -> option false ((=) name) (subject cert)


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
  let open Extension in
  match extn_basic_constr cert with
  | Some (_ , Basic_constraints (true, None))   -> true
  | Some (_ , Basic_constraints (true, Some n)) -> n >= pathlen
  | _                                           -> false

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
      (* key_encipherment (RSA) *)
      (* signing (DHE_RSA) *)
      | (_, Key_usage usage    ) -> List.mem Key_encipherment usage
      | (_, Ext_key_usage usage) -> List.mem Server_auth usage
      | (c, Policies ps        ) -> not c || List.mem `Any ps
      (* we've to deal with _all_ extensions marked critical! *)
      | (crit, _)                -> not crit )
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

let is_ca_cert_valid now cert =
  Printf.printf "verifying CA cert %s: " (common_name_to_string cert.asn);
  match
    is_self_signed cert,
    validate_signature cert cert,
    validate_time now cert,
    validate_ca_extensions cert
  with
  | (true, true, true, true) -> success
  | (false, _, _, _)         -> fail InvalidCA
  | (_, false, _, _)         -> fail InvalidSignature
  | (_, _, false, _)         -> fail CertificateExpired
  | (_, _, _, false)         -> fail InvalidExtensions

let is_server_cert_valid ?host now cert =
  Printf.printf "verify server certificate %s\n"
                (common_name_to_string cert.asn);
  match
    validate_time now cert,
    option false (hostname_matches cert) host,
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
    Some (_, Subject_key_id au)                -> Utils.cs_eq auth au
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
  match List.filter (fun p -> issuer_matches_subject p cert) trusted with
  | []  -> None
  | [t] -> ( match ext_authority_matches_subject t cert with
             | true  -> Some t
             | false -> None )
  | _   -> None


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

let verify_chain_of_trust ?host ~time ~anchors (server, certs) =
  let res =
    let rec climb pathlen cert = function
      | super :: certs ->
          signs pathlen super cert >>= fun () ->
          climb (succ pathlen) super certs
      | [] ->
          match find_issuer anchors cert with
          | None when is_self_signed cert             -> fail SelfSigned
          | None                                      -> fail NoTrustAnchor
          | Some anchor when validate_time time anchor ->
              signs pathlen anchor cert
          | Some _                                    -> fail CertificateExpired
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
