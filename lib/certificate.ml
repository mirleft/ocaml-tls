open Registry
open Asn_grammars
open Asn

type certificate_failure =
  | InvalidCertificate
  | InvalidSignature
  | InvalidServerName

type verification_result = [
  | `Fail of certificate_failure
  | `Ok
]

(* more X509v3 extensions fun:

  - basicconstraints - ca bool - pathlenconstraint int option (verification depth limited - not counting the server cert, only intermediate)

 *)
(* stuff from 4366 (TLS extensions):
  - hostname extension [list of hostnames] (generally known as SNI)
    (send from _client_ to _server_,
     server may then choose a suitable certificate)
    "HostName" contains the fully qualified DNS hostname of the server,
    as understood by the client.  The hostname is represented as a byte
    string using UTF-8 encoding [UTF8], without a trailing dot.

  - OCSP [rfc 6520]
  - root CAs
  - client cert url

*)

(* CRL
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

do not forget about 'authority information access' (private internet extension -- 4.2.2 of 5280)
 *)

(*
2.5.29.32 - Certificate Policies
2.5.29.33 - Policy Mappings
2.5.29.36 - Policy Constraints
 *)
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

let validate_signature : certificate -> certificate -> Cstruct.t -> bool =
  fun trusted c raw ->
    assert (c.signature_algo = c.tbs_cert.signature);
    (* we'll first try the short way and look up certificate authority key identifier from extensions *)
    let issuing_key = rsa_public_of_cert trusted in
    (* we have to check that issuing_key was really the one used to sign this certificate *)
    (* issuer of c should be subject of trusted! *)
(*
      * country,
      * organization,
      * organizational unit,
      * distinguished name qualifier,
      * state or province name,
      * common name (e.g., "Susan Housley"), and
      * serial number.

   In addition, implementations of this specification SHOULD be prepared
   to receive the following standard attribute types in issuer and
   subject names:

      * locality,
      * title,
      * surname,
      * given name,
      * initials,
      * pseudonym, and
      * generation qualifier (e.g., "Jr.", "3rd", or "IV").

   In addition, implementations of this specification MUST be prepared
   to receive the domainComponent attribute, as defined in [RFC4519].

 *)

(*
ISSUER outer loop
 inner loop
  oid 2.5.4.10 val Root CA
ISSUER outer loop
 inner loop
  oid 2.5.4.11 val http://www.cacert.org
ISSUER outer loop
 inner loop
  oid 2.5.4.3 val CA Cert Signing Authority
ISSUER outer loop
 inner loop
  oid 1.2.840.113549.1.9.1 val support@cacert.org *)


    (* if c.extensions contains 2.5.29.35 - Authority Key Identifier check
       that it is the same as
       trusted.extensions 2.5.29.14 - Subject Key Identifier *)

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
      Printf.printf "comparing hash";
      Cstruct.hexdump hash;
      Cstruct.hexdump chash;
      Utils.cs_eq chash hash in

    match c.signature_algo with
    | MD5_RSA  -> comparing_hash Crypto.md5
    | SHA1_RSA -> comparing_hash Crypto.sha
    | _        -> false


let validate_time now cert =
  let from, till = cert.validity in
(* TODO:  from < now && now < till *)
  true

let basic_verification_with_a_really_long_name_which_fits_the_bill_ever_since_we_all_got_new_retina_displays_and_use_terminals_with_much_much_more_than_80_characters now name cert =
  Printf.printf "basic verify certificate\n";
                                      (* w *)
  List.iter (fun i -> Printf.printf "ISSUER outer loop\n";
                                                                                                                                            (* t *)
                      List.iter (fun j -> Printf.printf " inner loop\n";
                                          let id, name = j in
                                          Printf.printf "  oid %s val %s\n"

                                                                                                                                                                                                                                                                                                                                                            (* f *)
                                                        (String.concat "." (List.map string_of_int (OID.to_list id)))
                                                        name)
                                i)
            cert.issuer;
  List.iter (fun i -> Printf.printf "SUBJECT outer loop\n";
                      List.iter (fun j -> Printf.printf " inner loop\n";
                                          let id, name = j in
                                          Printf.printf "  oid %s val %s\n"
                                                        (String.concat "." (List.map string_of_int (OID.to_list id)))
                                                        name)
                                i)
            cert.subject;
  (match cert.extensions with
   | [] -> Printf.printf "no extensions\n"
   | xs ->
      List.iter (fun i ->
                   Printf.printf "EXTENSION\n";
                   let id, x, r = i in
                   Printf.printf "  oid %s x %s"
                                 (String.concat "." (List.map string_of_int (OID.to_list id)))
                                 (string_of_bool x);
                   Cstruct.hexdump r)
                xs );
  (match cert.issuer_id with
   | Some x -> Printf.printf "issuer id"; Cstruct.hexdump x
   | None -> Printf.printf "no issuer id\n");
  (match cert.subject_id with
   | Some x -> Printf.printf "subject id"; Cstruct.hexdump x
   | None -> Printf.printf "no subject id\n");
  validate_time now cert

let verify_certificate : certificate -> float -> string -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
  Printf.printf "verify certificate\n";
(*
2.5.29.15 - Key Usage
2.5.29.19 - Basic Constraints
2.5.29.30 - Name Constraints
2.5.29.37 - Extended key usage
 - good for signing
 - all should have CA = true in Basic Constraints
 - name constraints should match servername

      (n)  If a key usage extension is present, verify that the
           keyCertSign bit is set.
 *)
    if validate_signature trusted c raw then
      let cert = c.tbs_cert in
      if basic_verification_with_a_really_long_name_which_fits_the_bill_ever_since_we_all_got_new_retina_displays_and_use_terminals_with_much_much_more_than_80_characters now servername cert then
        `Ok
      else
        `Fail InvalidCertificate
    else
      `Fail InvalidSignature

let find_trusted_certs : unit -> certificate list =
  fun () ->
    let ca = Crypto_utils.cert_of_file "../certificates/ca.crt" in
(*    let ca = Crypto_utils.cert_of_file "../mirage-server/server.pem" in *)
    [ca]

let get_extension cert oid =
  match
    List.filter (fun (o, _, _) -> o = oid) cert.extensions
  with
  | [(_, crit, value)] -> Some (value, crit)
  | [] -> None
  | _  -> invalid_arg "Hodie Natus Est Radici Frater"

let get_subject_oid c oid =
  let rec go = function
    | (id, va)::_ when id = oid -> Some va
    | _ ::xs -> go xs
    | [] -> None in
  go (List.concat c.subject)


let get_cn : tBSCertificate -> string option =
  fun c ->
    let oid = OID.(base 2 5 <| 4 <| 3) in
    get_subject_oid c oid

let hostname_matches : tBSCertificate -> string -> bool =
(* - might include wildcards and international domain names *)
  fun c servername ->
    let subaltname = OID.(base 2 5 <| 29 <| 17) in
    (match get_extension c subaltname with
    | None -> (* use common name *)
       (match get_cn c with
        | None -> Printf.printf "did not find a CN\n"
        | Some cn -> Printf.printf "COMMON NAME %s\n" cn)
    | Some (names, _) -> Printf.printf "found subaltname"; Cstruct.hexdump names);
    (* that's now a choice -- http://www.alvestrand.no/objectid/2.5.29.17.html *)
    true

let verify_server_certificate : certificate -> float -> string -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
(*
 - key usage basic constraint: certificate should be good for
   - signing (DHE_RSA)
   - encryption (RSA)
 - there's also extended key usage
    (TLS web server authentication / TLS web client authentication/...)

2.5.29.15 - Key Usage
2.5.29.19 - Basic Constraints
2.5.29.30 - Name Constraints
2.5.29.37 - Extended key usage

 - might include wildcards
 - the emailAddress in subject should match expected values ??
 *)
  (* first things first: valid signature, unwarp tbscert: validity timestamps,... *)
  Printf.printf "verify server certificate\n";
  if validate_signature trusted c raw then
    let cert = c.tbs_cert in
    if basic_verification_with_a_really_long_name_which_fits_the_bill_ever_since_we_all_got_new_retina_displays_and_use_terminals_with_much_much_more_than_80_characters now servername cert then
      if hostname_matches cert servername then
        `Ok
      else
        `Fail InvalidServerName
    else
      `Fail InvalidCertificate
  else
    `Fail InvalidSignature

let verify_top_certificate : certificate list -> float -> string -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
  (* first have to find issuer of ``c`` in ``trusted`` *)
    Printf.printf "verify top certificate\n";
    let issuer = List.hd trusted in
    if validate_signature issuer c raw then
      let cert = c.tbs_cert in
      if basic_verification_with_a_really_long_name_which_fits_the_bill_ever_since_we_all_got_new_retina_displays_and_use_terminals_with_much_much_more_than_80_characters now servername cert then
        `Ok
      else
        `Fail InvalidCertificate
    else
      `Fail InvalidSignature


(* this is the API for a user (Cstruct.t list will go away) *)
let verify_certificates : string -> certificate list -> Cstruct.t list -> verification_result =
  fun servername cs packets ->
    (* we get a certificate chain, and the first is the server *)
    (* thus we need to reverse the list
        - check that the first is signed by some CA we know and trust

        - check next to be signed by previous (look into issuer)
        - certificate verification lists...
    *)
    let now = Sys.time () in
    let rec go t = function
      | []    -> (`Ok, t)
      | (c, p)::cs -> (* check that x is signed by x - 1 *)
         match verify_certificate t now servername c p with
         | `Ok  -> go c cs
         | `Fail x -> (`Fail x, c)
    in
    let trusted = find_trusted_certs () in
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
