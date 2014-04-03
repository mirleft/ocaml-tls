open Registry
open Asn_grammars
open Asn
open Utils

open Nocrypto

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

let success = Or_error.return ()

let lower = function
  | Or_error.Ok ()     -> `Ok
  | Or_error.Error err -> `Fail err

(* TODO RFC 5280: A certificate MUST NOT include more than
                  one instance of a particular extension. *)

let issuer_matches_subject parent cert =
  Name.equal parent.tbs_cert.subject cert.tbs_cert.issuer

let is_self_signed cert = issuer_matches_subject cert cert

let subject cert =
  map_find cert.tbs_cert.subject
           ~f:(function Name.CN n -> Some n | _ -> None)

let common_name_to_string cert =
  match subject cert with
  | None   -> "NO commonName:" ^ Utils.hexdump_to_str cert.signature_val
  | Some x -> x

let hostname_matches cert name =
  let open Extension in
  match extn_subject_alt_name cert with
  | Some (_, Subject_alt_name names) ->
      List.exists
        (function General_name.DNS x -> x = name | _ -> false)
        names
  | _ -> option false ((=) name) (subject cert)


(* XXX should return the tbs_cert blob from the parser, this is insane *)
let raw_cert_hack cert raw =
  let siglen = Cstruct.len cert.signature_val in
  let off    = if siglen > 128 then 1 else 0 in
  Cstruct.(sub raw 4 (len raw - (siglen + 4 + 19 + off)))

let validate_signature trusted cert raw =
  let tbs_raw = raw_cert_hack cert raw in
  match trusted.tbs_cert.pk_info with

  | PK.RSA issuing_key ->

     ( match Crypto.verifyRSA_and_unpadPKCS1 issuing_key cert.signature_val with
       | Some signature ->
          ( match pkcs1_digest_info_of_cstruct signature with
            | None              -> false
            | Some (algo, hash) ->
               let compare_hashes hashfn = Utils.cs_eq hash (hashfn tbs_raw) in
               let open Algorithm in
               match (cert.signature_algo, algo) with
               | (MD5_RSA , MD5 ) -> compare_hashes Hash.MD5.digest
               | (SHA1_RSA, SHA1) -> compare_hashes Hash.SHA1.digest
               | _ -> false )
       | None -> false )

  | _ -> false

let validate_time now cert =
(*   let from, till = cert.validity in *)
(* TODO:  from < now && now < till *)
  true

let validate_path_len pathlen cert =
  let open Extension in
  match extn_basic_constr cert with
  | Some (_ , Basic_constraints (true, None))   -> true
  | Some (_ , Basic_constraints (true, Some n)) -> n >= pathlen
  | _                                           -> false

let validate_ca_extensions cert =
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

let validate_server_extensions cert =
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
                  (common_name_to_string cert);
    match
      validate_time now cert,
      validate_ca_extensions cert
    with
    | (true, true) -> success
    | (false, _)   -> Or_error.fail CertificateExpired
    | (_, false)   -> Or_error.fail InvalidExtensions

let is_ca_cert_valid now cert raw =
  Printf.printf "verifying CA cert %s: " (common_name_to_string cert);
  match
    is_self_signed cert,
    validate_signature cert cert raw,
    validate_time now cert,
    validate_ca_extensions cert
  with
  | (true, true, true, true) -> success
  | (false, _, _, _)         -> Or_error.fail InvalidCA
  | (_, false, _, _)         -> Or_error.fail InvalidSignature
  | (_, _, false, _)         -> Or_error.fail CertificateExpired
  | (_, _, _, false)         -> Or_error.fail InvalidExtensions

let is_server_cert_valid ?servername now cert =
  Printf.printf "verify server certificate %s\n"
                (common_name_to_string cert);
  match
    validate_time now cert,
    option false (hostname_matches cert) servername,
    validate_server_extensions cert
  with
  | (true, true, true) -> success
  | (false, _, _)      -> Or_error.fail CertificateExpired
  | (_, false, _)      -> Or_error.fail InvalidServerName
  | (_, _, false)      -> Or_error.fail InvalidServerExtensions


let ext_authority_matches_subject trusted cert =
  let open Extension in
  match
    extn_authority_key_id cert, extn_subject_key_id trusted
  with
  | Some (_, Authority_key_id (Some auth, _, _)),
    Some (_, Subject_key_id au)                -> Utils.cs_eq auth au
  (* TODO: check exact rules in RFC5280 *)
  | Some (_, Authority_key_id (None, _, _)), _ -> true (* not mandatory *)
  | None, _                                    -> true (* not mandatory *)
  | _, _                                       -> false

let signs pathlen trusted cert raw_cert =
  Printf.printf "verifying relation of %s -> %s (pathlen %d)\n"
                (common_name_to_string trusted)
                (common_name_to_string cert)
                pathlen;
  match
    issuer_matches_subject trusted cert,
    ext_authority_matches_subject trusted cert,
    validate_signature trusted cert raw_cert,
    validate_path_len pathlen trusted
  with
  | (true, true, true, true) -> success
  | (false, _, _, _)         -> Or_error.fail InvalidCertificate
  | (_, false, _, _)         -> Or_error.fail InvalidExtensions
  | (_, _, false, _)         -> Or_error.fail InvalidSignature
  | (_, _, _, false)         -> Or_error.fail InvalidPathlen


let find_issuer trusted cert =
  (* first have to find issuer of ``c`` in ``trusted`` *)
  Printf.printf "looking for issuer of %s (%d CAs)\n"
                (common_name_to_string cert)
                (List.length trusted);
  match List.filter (fun p -> issuer_matches_subject p cert) trusted with
  | []  -> None
  | [t] -> ( match ext_authority_matches_subject t cert with
             | true  -> Some t
             | false -> None )
  | _   -> None


(* this is the API for the user (Cstruct.t will go away) *)
let verify_certificates ?servername ~time ~anchors = function
  | []                                    -> `Fail InvalidInput
  | (server, server_raw) :: certs_and_raw ->
      let open Or_error in

      let rec climb pathlen cert cert_raw = function
        | (super, super_raw) :: certs ->
            signs pathlen super cert cert_raw >>= fun () ->
            climb (succ pathlen) super super_raw certs
        | [] ->
            match find_issuer anchors cert with
            | None when is_self_signed cert             -> fail SelfSigned
            | None                                      -> fail NoTrustAnchor
            | Some anchor when validate_time time anchor ->
                signs pathlen anchor cert cert_raw
            | Some _                                    -> fail CertificateExpired
      in

      let res =
        is_server_cert_valid ?servername time server     >>= fun () ->
        mapM_ (o (is_cert_valid time) fst) certs_and_raw >>= fun () ->
        climb 0 server server_raw certs_and_raw
      in lower res



(* XXX OHHH, i soooo want to be parameterized by (pre-parsed) trusted certs...  *)
let find_trusted_certs now =
  let cacert_file, ca_nss_file =
    ("certificates/cacert.crt", "certificates/ca-root-nss.crt") in
  let ((cacert, raw), nss) =
    Crypto_utils.(cert_of_file cacert_file, certs_of_file ca_nss_file) in

  let cas   = List.append nss [(cacert, raw)] in
  let valid = List.filter (fun (cert, raw) ->
                  Or_error.is_success @@ is_ca_cert_valid now cert raw)
                cas in
  Printf.printf "read %d certificates, could validate %d\n" (List.length cas) (List.length valid);
  let certs, _ = List.split valid in
  certs

let verify_certificates_debug ?servername chain =
  let time    = Unix.gettimeofday () in
  let anchors = find_trusted_certs time in
  verify_certificates ?servername ~time ~anchors chain


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
