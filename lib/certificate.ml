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

let validate_signature : certificate -> certificate -> Cstruct.t -> bool =
  fun trusted c raw ->
    assert (c.signature_algo = c.tbs_cert.signature);
    (* we'll first try the short way and look up certificate authority key identifier from extensions *)
    let issuing_key = rsa_public_of_cert trusted (*match __ with
      | Some x -> x
      | None ->     (* otherwise we use the issuer field *) *)
    in
    (* we have to check that issuing_key was really the one used to sign this certificate *)

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
        Printf.printf "comparing md5";
        Cstruct.hexdump hash;
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
          Printf.printf "comparing sha1";
          Cstruct.hexdump hash;
          Cstruct.hexdump chash;
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
  Printf.printf "basic verify certificate\n";
  List.iter (fun i -> Printf.printf "ISSUER outer loop\n";
                      List.iter (fun j -> Printf.printf " inner loop\n";
                                          let id, name = j in
                                          Printf.printf "  oid %s val %s\n"
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
   | Some x ->
      List.iter (fun i ->
                   Printf.printf "EXTENSION\n";
                   let id, x, r = i in
                   Printf.printf "  oid %s x %s"
                                 (String.concat "." (List.map string_of_int (OID.to_list id)))
                                 (string_of_bool x);
                   Cstruct.hexdump r)
                x;
   | None -> Printf.printf "no extensions\n");
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

let verify_server_certificate : certificate -> float -> string -> certificate -> Cstruct.t -> verification_result =
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
  Printf.printf "verify server certificate\n";
  if validate_signature trusted c raw then
    let cert = c.tbs_cert in
    if basic_verification now servername cert then
      `Ok
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
      if basic_verification now servername cert then
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
