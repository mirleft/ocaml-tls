open Asn_grammars
open Asn

open Asn_grammars.ID

type certificate_failure =
  | InvalidCertificate
  | InvalidSignature

type verification_result = [
  | `Fail of certificate_failure
  | `Ok
]

let validate_signature : certificate list -> certificate -> Cstruct.t -> bool =
  fun trusted c raw ->
    assert (c.signature_algo = c.tbs_cert.signature);
    (* try to find the public key of the issuer *)
    (* we'll first try the short way and look up certificate authority key identifier from extensions *)
    let issuing_key = rsa_public_of_cert (List.hd trusted) (*match __ with
      | Some x -> x
      | None ->     (* otherwise we use the issuer field *) *)
    in
    (* XXX: this is awful code! *)
    let siglen = Cstruct.len c.signature in
    (* not sure whether 128 is what we want here, for sure we just want to translate the certificate to a cstruct ;) *)
    let off = if siglen > 128 then 1 else 0 in
    (* 4 is the prefix-seq, 19 the sig oid *)
    let to_hash = Cstruct.sub raw 4 ((Cstruct.len raw) - (siglen + 4 + 19 + off)) in
    (* this results in a different encoding than the original certificate *)
    (* let dat = tbs_certificate_to_cstruct c.tbs_cert in
       assert (Utils.cs_eq to_hash dat); *) (* david: this fails *)
    if c.signature_algo = md5WithRSAEncryption then
      begin
        let signature = Crypto.verifyRSA_and_unpadPKCS1 34 issuing_key c.signature in
        let algo, hash = match pkcs1_digest_info_of_cstruct signature with
          | Some ((a, b), _) -> (a, b)
          | None -> assert false
        in
        assert (algo = id_md5);
        let chash = Crypto.md5 to_hash in
        Printf.printf "hash";
        Cstruct.hexdump hash;
        Printf.printf "chash";
        Cstruct.hexdump chash;
        assert (Utils.cs_eq chash hash);
        true
      end
    else
      if c.signature_algo = sha1WithRSAEncryption then
        begin
          let signature = Crypto.verifyRSA_and_unpadPKCS1 35 issuing_key c.signature in
          let algo, hash = match pkcs1_digest_info_of_cstruct signature with
            | Some ((a, b), _) -> (a, b)
            | None -> assert false
          in
          assert (algo = id_sha1);
          let chash = Crypto.sha to_hash in
          assert (Utils.cs_eq chash hash);
          true
        end
      else
        begin
          Printf.printf "unknown algorithm: %s\n"
                        (String.concat " " (List.map string_of_int (OID.to_list c.signature_algo)));
          false
        end

let validate_time now cert =
  let from, till = cert.validity in
(* TODO:  from < now && now < till *)
  true

let basic_verification now name cert =
  validate_time now cert

let verify_certificate : certificate list -> float -> string -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
(*
 - good for signing
 - all should have CA = true in Basic Constraints
 - name constraints should match servername
 *)
    if validate_signature trusted c raw then
      let cert = c.tbs_cert in
      if basic_verification now servername cert then
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

let verify_server_certificate : certificate list -> float -> string -> certificate -> Cstruct.t -> verification_result =
  fun trusted now servername c raw ->
(*
 - key usage basic constraint: certificate should be good for
   - signing (DHE_RSA)
   - encryption (RSA)
 - there's also extended key usage
    (TLS web server authentication / TLS web client authentication/...)

 - first look for subjectAltNames, then commonName for backwards compat, and find something matching the expected
 - might include wildcards
 - the emailAddress in subject should match expected values ??
 *)
  (* first things first: valid signature, unwarp tbscert: validity timestamps,... *)
  if validate_signature trusted c raw then
    let cert = c.tbs_cert in
    if basic_verification now servername cert then
      `Ok
    else
      `Fail InvalidCertificate
  else
    `Fail InvalidSignature

(* this is the API for a user (Cstruct.t list will go away) *)
let verify_certificates : string -> certificate list -> Cstruct.t list -> verification_result =
  fun servername cs packets ->
    (* in reality we get a certificate chain, and the first is the server *)
    (* thus we need to reverse the list
        - check that the first is signed by some CA we know and trust
        - check next to be signed by previous (look into issuer)

        - certificate verification lists...
    *)
    let now = Sys.time () in
    let rec go trusted = function
      | []    -> verify_server_certificate trusted now servername (List.hd cs) (List.hd packets)
      | (c, p)::cs ->
         match verify_certificate trusted now servername c p with
         | `Ok  -> go [c] cs
         | `Fail x -> `Fail x
    in
    let trusted = find_trusted_certs () in
    go trusted (List.combine (List.rev (List.tl cs)) (List.rev (List.tl packets)))

(* - test setup (ACM CCS'12):
            self-signed cert with requested commonName,
            self-signed cert with other commonName,
            valid signed cert with other commonName
   - also of interest: international domain names, wildcards
 *)

(* alternative approach: interface and implementation for certificate pinning *)
(* alternative approach': notary system / perspectives *)
(* alternative approach'': static list of trusted certificates *)
