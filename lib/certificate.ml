open Registry
open Asn_grammars
open Asn
open Utils

type certificate_failure =
  | InvalidCertificate
  | InvalidSignature
  | InvalidServerName
  | SelfSigned
  | MultipleRootCA
  | NoTrustAnchor
  | NoServerName

type verification_result = [
  | `Fail of certificate_failure
  | `Ok
]


(* 5280 A certificate MUST NOT include more than one instance of a particular extension. *)

let issuer_matches_subject_tbs parent cert =
  Name.equal parent.subject cert.issuer

let issuer_matches_subject parent cert =
  issuer_matches_subject_tbs parent.tbs_cert cert.tbs_cert

let is_self_signed cert = issuer_matches_subject cert cert

(* XXX should return the tbc_cert blob from the parser, this is insane *)
let raw_cert_hack cert raw =
  let siglen = Cstruct.len cert.signature_val in
  let off    = if siglen > 128 then 1 else 0 in
  Cstruct.(sub raw 4 (len raw - (siglen + 4 + 19 + off)))

let validate_signature trusted cert raw =
  ( issuer_matches_subject trusted cert ) &&

  let tbs_raw = raw_cert_hack cert raw in
  match trusted.tbs_cert.pk_info with

  | PK.RSA issuing_key ->

      let signature = 
        Crypto.verifyRSA_and_unpadPKCS1 issuing_key cert.signature_val in

      match pkcs1_digest_info_of_cstruct signature with
      | None                   -> false
      | Some ((algo, hash), _) ->
          let compare_hashes hashfn = Utils.cs_eq hash (hashfn tbs_raw) in
          match (cert.signature_algo, algo) with
          | (MD5_RSA , MD5 ) -> compare_hashes Crypto.md5
          | (SHA1_RSA, SHA1) -> compare_hashes Crypto.sha
          | _ -> false

  | _ -> false


let validate_time now cert =
(*   let from, till = cert.validity in *)
(* TODO:  from < now && now < till *)
  true

let extn_exists getter cert =
  match getter cert with None -> false | Some _ -> true

let validate_ca_extensions cert =
  let open Extension in
  (* comments from RFC5280 *)
  (* 4.2.1.9 Basic Constraints *)
  (* Conforming CAs MUST include this extension in all CA certificates used *)
  (* to validate digital signatures on certificates and MUST mark the *)
  (* extension as critical in such certificates *)
  (* unfortunately, there are 12 CA certs (including the one which
      signed google.com) which are _NOT_ marked as critical *)
  ( extn_exists extn_basic_constr cert ) &&

  (* 4.2.1.3 Key Usage *)
  (* Conforming CAs MUST include key usage extension *)
  (* CA Cert (cacert.org) does not *)
  ( match extn_key_usage cert with
    (* When present, conforming CAs SHOULD mark this extension as critical *)
    (* yeah, you wish... *)
    | Some (crit, Key_usage usage) -> List.mem Key_cert_sign usage 
    | _                            -> false ) &&

  (* Name Constraints   - name constraints should match servername *)

  (* check criticality *)
  List.for_all
    (function | (true,  Key_usage _)         -> true
              | (true,  Basic_constraints _) -> true
              | (true,  _)                   -> false
              | (false, _)                   -> true )
    cert.tbs_cert.extensions


let ext_authority_matches_subject trusted cert =
  let open Extension in
  match
    extn_authority_key_id cert, extn_subject_key_id trusted
  with
  | Some (_, Authority_key_id (Some auth, _, _)),
    Some (_, Subject_key_id au) ->
      let res = Utils.cs_eq auth au in
      Printf.printf "SUB KEY ID and AUTH KEY ID matches? %s" (string_of_bool res);
      Cstruct.hexdump auth;
      Cstruct.hexdump au;
      res
  | (None | Some (_, Authority_key_id (None, _, _))), _ -> true (* it's not mandatory *)
  | _, _ -> false


let validate_intermediate_extensions trusted cert =
  (validate_ca_extensions cert) && (ext_authority_matches_subject trusted cert)

let validate_server_extensions trusted cert =
  let open Extension in
  ( List.for_all (function
      | (_, Basic_constraints (Some _)) -> false
        (* key_encipherment (RSA) *)
        (* signing (DHE_RSA) *)
      | (_, Key_usage usage) -> List.mem Key_encipherment usage
      | (_, Ext_key_usage usage) -> List.mem Server_auth usage
      | (true,  _) -> false (* we've to deal with _all_ extensions marked critical! *)
      | (false, _) -> true )
    cert.tbs_cert.extensions ) &&
  ext_authority_matches_subject trusted cert

let get_cn cert =
  map_find cert.subject
    ~f:Name.(function Common_name n -> Some n | _ -> None)

(* XXX return option? *)
let get_common_name cert =
  match get_cn cert.tbs_cert with
  | None   ->
     let sigl = Cstruct.len cert.signature_val in
     let sign = Cstruct.copy cert.signature_val 0 sigl in
     let hex = Cryptokit.(transform_string (Hexa.encode ()) sign) in
     "NO commonName " ^ hex
  | Some x -> x

let verify_certificate : certificate -> float -> string option -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername cert raw ->
    Printf.printf "verify certificate %s -> %s\n"
                  (get_common_name trusted)
                  (get_common_name cert);
    match
      validate_signature trusted cert raw &&
      validate_time now cert              &&
      validate_intermediate_extensions trusted cert
    with
    | true -> `Ok
    | _    -> `Fail InvalidCertificate

let verify_ca_cert now cert raw =
  Printf.printf "verifying CA cert %s: " (get_common_name cert);
  match
    validate_signature cert cert raw &&
    validate_time now cert           &&
    validate_ca_extensions cert
  with
  | true -> Printf.printf "ok\n";     true
  | _    -> Printf.printf "failed\n"; false

(* XXX OHHH, i soooo want to be parameterized by (pre-parsed) trusted certs...  *)
let find_trusted_certs : float -> certificate list = fun now ->

  let cacert_file, ca_nss_file =
    ("../certificates/cacert.crt", "../certificates/ca-root-nss.crt") in
  let ((cacert, raw), nss) =
    Crypto_utils.(cert_of_file cacert_file, certs_of_file ca_nss_file) in

  let cas   = List.append nss [(cacert, raw)] in
  let valid = List.filter (fun (cert, raw) -> verify_ca_cert now cert raw) cas in
  Printf.printf "read %d certificates, could validate %d\n" (List.length cas) (List.length valid);
  let certs, _ = List.split valid in
  certs

let hostname_matches cert name =
  let open Extension in
  ( match extn_subject_alt_name cert with
    | Some (_, Subject_alt_name names) ->
        List.exists
          (function General_name.DNS x -> x = name | _ -> false)
          names
    | _  -> false ) ||
  ( match get_cn cert.tbs_cert with
    | None   -> false
    | Some x -> x = name )

let verify_server_certificate : certificate -> float -> string option -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername cert raw ->
  Printf.printf "verify server certificate %s -> %s\n"
                (get_common_name trusted)
                (get_common_name cert);
  let smatches name cert = match name with
    | None   -> false
    | Some x -> hostname_matches cert x
  in
  match
    validate_signature trusted cert raw     &&
    validate_time now cert                  &&
    validate_server_extensions trusted cert &&
    smatches servername cert
  with
  | true ->
      Printf.printf "successfully verified server certificate\n";
      `Ok
  | _ ->
      Printf.printf "could not verify server certificate\n";
      `Fail InvalidCertificate

let verify_top_certificate : certificate list -> float -> string option -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
    (* first have to find issuer of ``c`` in ``trusted`` *)
    Printf.printf "verify top certificate %s (%d CAs)\n"
                  (get_common_name c)
                  (List.length trusted);
    match List.filter (fun p -> issuer_matches_subject p c) trusted with
     | []  -> Printf.printf "couldn't find trusted CA cert\n"; `Fail NoTrustAnchor
     | [t] -> verify_certificate t now servername c raw
     | _   -> Printf.printf "found multiple root CAs\n"; `Fail MultipleRootCA

(* this is the API for a user (Cstruct.t list might go away) *)
let verify_certificates : string option -> (certificate * Cstruct.t) list -> verification_result =
  fun servername -> function
    (* we get the certificate chain cs:
        [c0; c1; c2; ... ; cn]
        let server = c0
        let top = cn
       strategy:
        1. find a trusted CA for top and
             verify that trusted signed top
        2. verify intermediate certificates:
             verify that [cn .. c2] signed [cn-1 .. c1]
        3. verify server certificate was signed by c1 and
             server certificate has required servername *)
    (* short-path for self-signed certificate  *)
  | [] -> assert false (* NO, return the right error *)

  | [(cert, _)] when is_self_signed cert ->
      (* further verification of a self-signed certificate does not make sense:
         why should anyone handle a properly self-signed and valid certificate
         different from a badly signed invalid certificate? *)
      (Printf.printf "DANGER: self-signed certificate\n";
       `Fail SelfSigned)

  | (server, server_raw) :: certs_and_raw ->
      let now = Sys.time () in
      (* :( this is soooo foldr in a lazy setting... *)
      let rec go t = function
        | []         -> (`Ok, t)
        | (c, p)::cs -> (* step 2 *)
           match verify_certificate t now servername c p with
           | `Ok  -> go c cs
           | `Fail x -> (`Fail x, c)
      in
      let trusted = find_trusted_certs now in
      (* intermediate certificates *)
      match List.rev certs_and_raw with
      | (topc, topr) :: reversed ->
        (* step 1 *)
        ( match verify_top_certificate trusted now servername topc topr with
          | `Ok ->
            (* call step 2 *)
            (match go topc reversed with
              | (`Ok, t) ->
                (* step 3 *)
                verify_server_certificate t now servername server server_raw
              | (`Fail x, _) -> `Fail x)
          | `Fail x -> `Fail x )
      | _ -> assert false (* single cert, not self-signed case *)


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
