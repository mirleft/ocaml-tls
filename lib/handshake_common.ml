open Utils
open Core
open State

open Nocrypto

let empty = function [] -> true | _ -> false

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

let get_hostname_ext h =
  map_find
    h.extensions
    ~f:(function Hostname s -> Some s | _ -> None)

let hostname h : string option =
  match get_hostname_ext h with
  | Some (Some name) -> Some name
  | _                -> None

let get_secure_renegotiation exts =
  map_find
    exts
    ~f:(function SecureRenegotiation data -> Some data | _ -> None)

let empty_session = {
  server_random    = Cstruct.create 0 ;
  client_random    = Cstruct.create 0 ;
  client_version   = Supported TLS_1_2 ;
  ciphersuite      = `TLS_DHE_RSA_WITH_AES_256_CBC_SHA ;
  peer_certificate = [] ;
  trust_anchor     = None ;
  own_certificate  = [] ;
  own_private_key  = None ;
  own_name         = None ;
  master_secret    = Cstruct.create 0 ;
  renegotiation    = Cstruct.(create 0, create 0) ;
  client_auth      = false ;
}

let supported_protocol_version (min, max) v =
  match version_ge v min, version_ge v max with
    | _   , true -> Some max
    | true, _    -> any_version_to_version v
    | _   , _    -> None

let to_ext_type = function
  | Hostname _            -> `Hostname
  | MaxFragmentLength _   -> `MaxFragmentLength
  | EllipticCurves _      -> `EllipticCurves
  | ECPointFormats _      -> `ECPointFormats
  | SecureRenegotiation _ -> `SecureRenegotiation
  | Padding _             -> `Padding
  | SignatureAlgorithms _ -> `SignatureAlgorithms
  | UnknownExtension _    -> `UnknownExtension

let extension_types exts = List.(
  exts |> map to_ext_type
       |> filter @@ function `UnknownExtension -> false | _ -> true
  )

let not_multiple_same_extensions exts =
  List_set.is_proper_set (extension_types exts)

(* a server hello may only contain extensions which are also in the client hello *)
(*  RFC5246, 7.4.7.1
   An extension type MUST NOT appear in the ServerHello unless the same
   extension type appeared in the corresponding ClientHello.  If a
   client receives an extension type in ServerHello that it did not
   request in the associated ClientHello, it MUST abort the handshake
   with an unsupported_extension fatal alert. *)
let server_exts_subset_of_client sexts cexts =
  let (sexts', cexts') =
    (extension_types sexts, extension_types cexts) in
  List_set.subset sexts' cexts'
  &&
  let forbidden = function
    | `Padding | `SignatureAlgorithms -> true
    | _                               -> false in
  not (List.exists forbidden sexts')

let client_hello_valid ch =
  let open Ciphersuite in

  (* match ch.version with
    | TLS_1_0 ->
       if List.mem TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA ch.ciphersuites then
         return ()
       else
         fail HANDSHAKE_FAILURE
    | TLS_1_1 ->
       if List.mem TLS_RSA_WITH_3DES_EDE_CBC_SHA ch.ciphersuites then
         return ()
       else
         fail HANDSHAKE_FAILURE
    | TLS_1_2 ->
       if List.mem TLS_RSA_WITH_AES_128_CBC_SHA ch.ciphersuites then
         return ()
       else
         fail HANDSHAKE_FAILURE *)

  not (empty ch.ciphersuites)
  &&

  (List_set.is_proper_set ch.ciphersuites)
  &&

  (* TODO: if ecc ciphersuite, require ellipticcurves and ecpointformats extensions! *)
  not_multiple_same_extensions ch.extensions
  &&

  ( match ch.version with
    | Supported TLS_1_2 | TLS_1_X _                  -> true
    | SSL_3 | Supported TLS_1_0 | Supported TLS_1_1  ->
        let has_sig_algo =
          List.exists (function SignatureAlgorithms _ -> true | _ -> false)
            ch.extensions in
        not has_sig_algo )
  &&

  get_hostname_ext ch <> Some None

let server_hello_valid sh =
  let open Ciphersuite in

  not_multiple_same_extensions sh.extensions
  &&
  ( match get_hostname_ext sh with
    Some (Some _) -> false | _ -> true )
  (* TODO:
      - EC stuff must be present if EC ciphersuite chosen
   *)

let (<+>) = Cs.(<+>)

let signature version data sig_algs hashes private_key =
  match version with
  | TLS_1_0 | TLS_1_1 ->
    let data = Hash.MD5.digest data <+> Hash.SHA1.digest data in
    let signed = Rsa.PKCS1.sign private_key data in
    return (Writer.assemble_digitally_signed signed)
  | TLS_1_2 ->
    (* if no signature_algorithms extension is sent by the client,
       support for md5 and sha1 can be safely assumed! *)
    ( match sig_algs with
      | None              -> return `SHA1
      | Some client_algos ->
        let client_hashes =
          List.(map fst @@ filter (fun (_, x) -> x = Packet.RSA) client_algos)
        in
        match first_match client_hashes hashes with
        | None      -> fail (`Error (`NoConfiguredHash client_hashes))
        | Some hash -> return hash ) >|= fun hash_algo ->
    let hash = Hash.digest hash_algo data in
    let cs = X509.Certificate.pkcs1_digest_info_to_cstruct (hash_algo, hash) in
    let sign = Rsa.PKCS1.sign private_key cs in
    Writer.assemble_digitally_signed_1_2 hash_algo Packet.RSA sign

let peer_rsa_key = function
  | [] -> fail (`Fatal `NoCertificateReceived)
  | cert::_ ->
    match X509.Certificate.cert_pubkey cert with
    | Some (`RSA key) -> return key
    | _               -> fail (`Fatal `NotRSACertificate)

let verify_digitally_signed version data signature_data certificates =
  let signature_verifier version data =
    let open Reader in
    match version with
    | TLS_1_0 | TLS_1_1 ->
      ( match parse_digitally_signed data with
        | Or_error.Ok signature ->
          let compare_hashes should data =
            let computed_sig = Hash.MD5.digest data <+> Hash.SHA1.digest data in
            guard (Cs.equal should computed_sig) (`Fatal `RSASignatureMismatch)
          in
          return (signature, compare_hashes)
        | Or_error.Error re -> fail (`Fatal (`ReaderError re)) )
    | TLS_1_2 ->
      ( match parse_digitally_signed_1_2 data with
        | Or_error.Ok (hash_algo, Packet.RSA, signature) ->
          let compare_hashes should data =
            match X509.Certificate.pkcs1_digest_info_of_cstruct should with
            | Some (hash_algo', target) when hash_algo = hash_algo' ->
              guard (Crypto.digest_eq hash_algo ~target data) (`Fatal `RSASignatureMismatch)
            | _ -> fail (`Fatal `HashAlgorithmMismatch)
          in
          return (signature, compare_hashes)
        | Or_error.Ok _ -> fail (`Fatal `NotRSASignature)
        | Or_error.Error re -> fail (`Fatal (`ReaderError re)) )

  and signature pubkey raw_signature =
    match Rsa.PKCS1.verify pubkey raw_signature with
    | Some signature -> return signature
    | None -> fail (`Fatal `RSASignatureVerificationFailed)
  in

  signature_verifier version data >>= fun (raw_signature, verifier) ->
  peer_rsa_key certificates >>= fun pubkey ->
  signature pubkey raw_signature >>= fun signature ->
  verifier signature signature_data

let validate_chain authenticator certificates hostname =
  let authenticate authenticator host certificates =
    match authenticator ?host certificates with
    | `Fail err  -> fail (`Error (`AuthenticationFailure err))
    | `Ok anchor -> return anchor

  and key_size min cs =
    let check c =
      match X509.Certificate.cert_pubkey c with
      | Some (`RSA key) when Rsa.pub_bits key >= min -> true
      | _                                            -> false
    in
    guard (List.for_all check cs) (`Fatal `KeyTooSmall)

  and parse_certificates certs =
    let certificates = filter_map ~f:X509.Certificate.parse certs in
    guard (List.length certs = List.length certificates) (`Fatal `BadCertificateChain) >|= fun () ->
    certificates

  in

  (* RFC5246: must be x509v3, take signaturealgorithms into account! *)
  (* RFC2246/4346: is generally x509v3, signing algorithm for certificate _must_ be same as algorithm for certificate key *)
  parse_certificates certificates >>= fun certs ->
  match authenticator with
  | None ->
    return (certs, None)
  | Some authenticator ->
    authenticate authenticator hostname certs >>= fun anchor ->
    key_size Config.min_rsa_key_size certs >|= fun () ->
    (certs, anchor)
