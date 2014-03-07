open Registry
open Asn_grammars
open Asn

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

(*    2.16.840.1.113730.1.1 - Netscape certificate type
    2.16.840.1.113730.1.12 - SSL server name *)
(*    2.16.840.1.113730.1.13 - Netscape certificate comment *)

(* 5280::
   A certificate-using system MUST reject the certificate if it encounters
   a critical extension it does not recognize or a critical extension
   that contains information that it cannot process.  A non-critical
   extension MAY be ignored if it is not recognized, but MUST be
   processed if it is recognized.

   A certificate MUST NOT include more
   than one instance of a particular extension.
*)

let issuer_matches_subject_tbs : tBSCertificate -> tBSCertificate -> bool =
  fun p c -> Name.equal p.subject c.issuer

let issuer_matches_subject : certificate -> certificate -> bool =
  fun p c -> issuer_matches_subject_tbs p.tbs_cert c.tbs_cert

let is_self_signed : certificate -> bool =
  fun c -> issuer_matches_subject c c

let validate_signature : certificate -> certificate -> Cstruct.t -> bool =
  fun trusted c raw ->
   try (
    let issuing_key = match trusted.tbs_cert.pk_info with
      | PK.RSA key -> key
      |  _         -> assert false
    in

    (* issuer of c should be subject of trusted! *)
    assert (issuer_matches_subject trusted c);

    (* XXX: this is awful code! *)
    let siglen = Cstruct.len c.signature_val in
    (* not sure whether 128 is what we want here, for sure we just want to translate the certificate to a cstruct ;) *)
    let off = if siglen > 128 then 1 else 0 in
    (* 4 is the prefix-seq, 19 the sig oid *)
    let to_hash = Cstruct.sub raw 4 ((Cstruct.len raw) - (siglen + 4 + 19 + off)) in
    (* this results in a different encoding than the original certificate *)
    (* let dat = tbs_certificate_to_cstruct c.tbs_cert in
       assert (Utils.cs_eq to_hash dat); *) (* david: this fails *)
    let signature = Crypto.verifyRSA_and_unpadPKCS1 issuing_key c.signature_val in
    let algo, hash = match pkcs1_digest_info_of_cstruct signature with
      | Some ((a, b), _) -> (a, b)
      | None -> assert false
    in

    (* XXX move me outside of that comment up there? *)
    let comparing_hash hashfn =
      let chash = hashfn to_hash in
      Utils.cs_eq chash hash in

    let open Algorithm in
    match (c.signature_algo, algo) with
    | (MD5_RSA, MD5)   -> comparing_hash Crypto.md5
    | (SHA1_RSA, SHA1) -> comparing_hash Crypto.sha
    | _                -> false)
   with
   | _ -> false


let validate_time now cert =
  let from, till = cert.validity in
(* TODO:  from < now && now < till *)
  true

let rec find_by ~f = function
  | x::xs ->
    ( match f x with
      | None   -> find_by ~f xs
      | Some a -> Some a )
  | [] -> None

let validate_ca_extensions cert =
  try (
    let open Extension in
    (* comments from RFC5280 *)
    (* 4.2.1.9 Basic Constraints *)
    (* Conforming CAs MUST include this extension in all CA certificates used *)
    (* to validate digital signatures on certificates and MUST mark the *)
    (* extension as critical in such certificates *)
    let bc =
      function
      | (_, Basic_constraints _) -> true
      | _ -> false
    in
    assert (List.exists bc cert.extensions);

    (* 4.2.1.3 Key Usage *)
    (* Conforming CAs MUST include key usage extension *)
    let ku =
      function
      | (_, Key_usage k) ->
         (* When present, conforming CAs SHOULD mark this extension as critical *)
         (* yeah, you wish... *)
         List.exists (function
                       | Key_cert_sign -> true
                       | _ -> false) k
      | _ -> false
    in
    assert (List.exists ku cert.extensions);

    (* we've to deal with _all_ extensions marked critical! *)
    let rec ver_ext =
      function
      | [] -> true
      | (true, Key_usage _)::xs         -> ver_ext xs
      | (true, Basic_constraints _)::xs -> ver_ext xs
      | (true, e)::xs                   -> false
      | (false, e)::xs                  -> ver_ext xs
    in
    ver_ext cert.extensions) with
  | _ -> false

(* 2.5.29.30 - Name Constraints   - name constraints should match servername
   2.5.29.37 - Extended key usage *)

let validate_intermediate_extensions trusted cert =
  validate_ca_extensions cert
(* if c.extensions contains 2.5.29.35 - Authority Key Identifier check
   that it is the same as
   trusted.extensions 2.5.29.14 - Subject Key Identifier *)

let validate_server_extensions trusted cert =
(*
 - key usage basic constraint: certificate should be good for
   - signing (DHE_RSA)
   - encryption (RSA)
 - there's also extended key usage
    (TLS web server authentication / TLS web client authentication/...)

2.5.29.15 - Key Usage
2.5.29.19 - Basic Constraints
2.5.29.37 - Extended key usage
 *)
  true

let verify_certificate : certificate -> float -> string option -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
    Printf.printf "verify certificate\n";
    let cert = c.tbs_cert in
    match (validate_signature trusted c raw,
           validate_time now cert,
           validate_intermediate_extensions trusted.tbs_cert cert) with
    | (true, true, true) -> `Ok
    | _ -> `Fail InvalidCertificate

let get_cn cert =
  find_by cert.subject
    ~f:Name.(function Common_name n -> Some n | _ -> None)

let verify_ca_cert now cert raw =
  let tbs = cert.tbs_cert in
  (validate_signature cert cert raw) &&
    (validate_time now tbs) &&
      (validate_ca_extensions tbs)

let find_trusted_certs : float -> certificate list =
  fun now ->
    let cacert, raw = Crypto_utils.cert_of_file "../certificates/cacert.crt" in
    let nss = Crypto_utils.certs_of_file "../certificates/ca-root-nss.crt" in
    let cas = List.append nss [(cacert, raw)] in
    let valid =
      List.filter (fun (cert, raw) ->
                   (match get_cn cert.tbs_cert with
                    | None   -> Printf.printf "no common name found ";
                    | Some x -> Printf.printf "inserted cert with CN %s " x);
                   if verify_ca_cert now cert raw then
                     (Printf.printf "validated signature\n";
                      true)
                   else
                     (Printf.printf "couldn't validate signature\n";
                      false))
                  cas;
    in
    Printf.printf "read %d certificates, could validate %d\n" (List.length cas) (List.length valid);
    let certs, _ = List.split valid in
    certs

let hostname_matches : tBSCertificate -> string -> bool =
  fun _ _ -> true
(* - might include wildcards and international domain names *)
(*   fun c servername ->
    let subaltname = OID.(base 2 5 <| 29 <| 17) in
    (match get_extension c subaltname with
    | None -> |+ use common name +|
       (match get_cn c with
        | None -> Printf.printf "did not find a CN\n"
        | Some cn -> Printf.printf "COMMON NAME %s\n" cn)
    | Some (names, _) -> Printf.printf "found subaltname"; Cstruct.hexdump names);
    |+ that's now a choice -- http://www.alvestrand.no/objectid/2.5.29.17.html +|
    true *)

let verify_server_certificate : certificate -> float -> string option -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
  (* first things first: valid signature, unwarp tbscert: validity timestamps,... *)
  Printf.printf "verify server certificate\n";
  let cert = c.tbs_cert in
  let smatches = fun name c ->
    match name with
    | None   -> false
    | Some x -> hostname_matches c x
  in
  match (validate_signature trusted c raw,
         validate_time now cert,
         validate_server_extensions trusted.tbs_cert cert,
         smatches servername cert) with
      | (true, true, true, true) ->
         Printf.printf "successfully verified server certificate\n";
         `Ok
      | (_, _, _, _) ->
         Printf.printf "could not verify server certificate\n";
         `Fail InvalidCertificate

let verify_top_certificate : certificate list -> float -> string option -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
  (* first have to find issuer of ``c`` in ``trusted`` *)
    Printf.printf "verify top certificate\n";
    match List.filter (fun p -> issuer_matches_subject p c) trusted with
     | []  -> Printf.printf "couldn't find trusted CA cert\n"; `Fail NoTrustAnchor
     | [t] -> verify_certificate t now servername c raw
     | _   -> Printf.printf "found multiple root CAs\n"; `Fail MultipleRootCA

(* this is the API for a user (Cstruct.t list will go away) *)
let verify_certificates : string option -> certificate list -> Cstruct.t list -> verification_result =
  fun servername cs packets ->
    (* we get a certificate chain, and the first is the server certificate *)
    (* thus we need to reverse the list
        - check that the first is signed by some CA we know and trust
        - check next to be signed by previous (look into issuer) *)
    (* short-path for self-signed certificate  *)
    if (List.length cs = 1) && is_self_signed (List.hd cs) then
      (* further verification of a self-signed certificate does not make sense:
         why should anyone handle a properly self-signed and valid certificate
         different from a badly signed invalid certificate? *)
      (Printf.printf "DANGER: self-signed certificate\n";
       `Fail SelfSigned)
    else
      let now = Sys.time () in
      let rec go t = function
        | []    -> (`Ok, t)
        | (c, p)::cs -> (* check that x is signed by x - 1 *)
           match verify_certificate t now servername c p with
           | `Ok  -> go c cs
           | `Fail x -> (`Fail x, c)
      in
      let trusted = find_trusted_certs now in
      let reversed = List.combine (List.rev (List.tl cs)) (List.rev (List.tl packets)) in
      let topc, topr = List.hd reversed in
      (* check that top one is signed by a trust anchor *)
      match verify_top_certificate trusted now servername topc topr with
      | `Ok -> (match go topc (List.tl reversed) (* checking rest of chain *) with
                | (`Ok, t) -> verify_server_certificate t now servername (List.hd cs) (List.hd packets) (* check server certificate *)
                | (`Fail x, _) -> `Fail x)
      | `Fail x -> `Fail x

(* - test setup (ACM CCS'12):
            self-signed cert with requested commonName,
            self-signed cert with other commonName,
            valid signed cert with other commonName
   - also of interest: international domain names, wildcards *)

(* alternative approach: interface and implementation for certificate pinning *)
(* alternative approach': notary system / perspectives *)
(* alternative approach'': static list of trusted certificates *)
