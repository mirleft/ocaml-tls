open Core
open Asn_grammars
open Asn

type certificate_verification_result = [
  | `Fail of Packet.alert_type
  | `Ok
]

let sha1oid =
  (* that's sha1 object id der encoded in hex *)
  let nums = [0x30; 0x21; 0x30; 0x09; 0x06; 0x05; 0x2b; 0x0e; 0x03; 0x02; 0x1a; 0x05; 0x00; 0x04; 0x14] in
  let res = Cstruct.create 15 in
  for i = 0 to 14 do
    Cstruct.set_uint8 res i (List.nth nums i)
  done;
  res

let validate_signature : certificate -> Cstruct.t -> certificate_verification_result =
  fun c raw ->
    let algorithm = OID.to_list c.signature_algo in
    assert (algorithm = (OID.to_list c.tbs_cert.signature));
    match algorithm with
      | [1; 2; 840; 113549; 1; 1; 4] ->
         Printf.printf "RSA-MD5\n";
         `Fail Packet.UNSUPPORTED_CERTIFICATE
      | [1; 2; 840; 113549; 1; 1; 5] ->
         let pubkey = rsa_public_of_cert c in
         let signature = Crypto.verifyRSA_and_unpadPKCS1 35 pubkey c.signature in
         let algo, hash = Cstruct.split signature 15 in
         assert (Utils.cs_eq algo sha1oid);
         (* this results in a different encoding than the original certificate *)
(*         let dat = tbs_certificate_to_cstruct c.tbs_cert in *)
         (* TODO: hardcoded numbers -- for 1024 bit RSA keys... *)
         let to_hash = Cstruct.sub raw 4 ((Cstruct.len raw) - 151) in
         let chash = Crypto.sha to_hash in
         assert (Utils.cs_eq chash hash);
         `Ok
      | x -> Printf.printf "unknown algorithm: %s\n"
                           (String.concat " " (List.map string_of_int x));
             `Fail Packet.UNSUPPORTED_CERTIFICATE

let validate_certificate : certificate -> Cstruct.t -> certificate_verification_result =
  fun c raw ->
    validate_signature c raw

let validate_certificates : certificate list -> Cstruct.t list -> certificate_verification_result =
  fun cs packets ->
    (* in reality we get a certificate chain, and the first is the server *)
    (* thus we need to reverse the list
        - check that the first is signed by some CA we know and trust
        - check next to be signed by previous (look into issuer)

        - all apart from the last certificate should have CA = true in Basic Constraints
        - the basic constraints also might contain name constraints
        - and key usage! good for signing or encryption, dependending on what the selected KEX needs
        - first look for subjectAltNames, then commonName for backwards compat, and find something matching the expected
        - might include wildcards, which might be complex regarding international domain names
        - the emailAddress in subject should match expected values

        - certificate verification lists...

        - alternative approach: interface and implementation for certificate pinning

        - test setup:
            self-signed cert with requested commonName,
            self-signed cert with other commonName,
            valid signed cert with other commonName
    *)
    let rec go = function
      | []    -> `Ok
      | (c, p)::cs ->
         match validate_certificate c p with
         | `Ok   -> go cs
         | `Fail x -> `Fail x
    in
    go (List.combine cs packets)
