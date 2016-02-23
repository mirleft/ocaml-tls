open Utils
open Core
open State

open Nocrypto

let downgrade13 = Uncommon.Cs.of_hex "44 4F 57 4E 47 52 44 01"
let downgrade12 = Uncommon.Cs.of_hex "44 4F 57 4E 47 52 44 00"

let trace_cipher cipher =
  let kex, papr = Ciphersuite.get_kex_privprot cipher in
  let sexp = lazy (Sexplib.Sexp.(List Ciphersuite.(
      [ sexp_of_key_exchange_algorithm kex ;
        sexp_of_payload_protection papr ])))
  in
  Tracing.sexp ~tag:"cipher" sexp

let empty = function [] -> true | _ -> false

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

let hostname (h : client_hello) : string option =
  map_find ~f:(function `Hostname s -> Some s | _ -> None) h.extensions

let get_secure_renegotiation exts =
  map_find
    exts
    ~f:(function `SecureRenegotiation data -> Some data | _ -> None)

let empty_session = {
  server_random          = Cstruct.create 0 ;
  client_random          = Cstruct.create 0 ;
  client_version         = Supported TLS_1_2 ;
  ciphersuite            = `TLS_DHE_RSA_WITH_AES_256_CBC_SHA ;
  peer_certificate_chain = [] ;
  peer_certificate       = None ;
  trust_anchor           = None ;
  received_certificates  = [] ;
  own_certificate        = [] ;
  own_private_key        = None ;
  own_name               = None ;
  master_secret          = Cstruct.create 0 ;
  renegotiation          = Cstruct.(create 0, create 0) ;
  client_auth            = false ;
  session_id             = Cstruct.create 0 ;
  extended_ms            = false ;
  resumption_secret      = Cstruct.create 0 ;
  psk_id                 = Cstruct.create 0 ;
}

let session_of_epoch (epoch : epoch_data) : session_data = {
  empty_session with
  ciphersuite = epoch.ciphersuite ;
  peer_certificate = epoch.peer_certificate ;
  trust_anchor = epoch.trust_anchor ;
  own_certificate = epoch.own_certificate ;
  own_private_key = epoch.own_private_key ;
  received_certificates = epoch.received_certificates ;
  peer_certificate_chain = epoch.peer_certificate_chain ;
  master_secret = epoch.master_secret ;
  own_name = epoch.own_name ;
  session_id = epoch.session_id ;
  extended_ms = epoch.extended_ms ;
  resumption_secret = epoch.resumption_secret ;
  psk_id = epoch.psk_id ;
}

let supported_protocol_version (min, max) v =
  match version_ge v min, version_ge v max with
    | _   , true -> Some max
    | true, _    -> any_version_to_version v
    | _   , _    -> None

let to_client_ext_type = function
  | `Hostname _            -> `Hostname
  | `MaxFragmentLength _   -> `MaxFragmentLength
  | `SupportedGroups _     -> `SupportedGroups
  | `ECPointFormats _      -> `ECPointFormats
  | `SecureRenegotiation _ -> `SecureRenegotiation
  | `Padding _             -> `Padding
  | `SignatureAlgorithms _ -> `SignatureAlgorithms
  | `UnknownExtension _    -> `UnknownExtension
  | `ExtendedMasterSecret  -> `ExtendedMasterSecret
  | `KeyShare _            -> `KeyShare
  | `EarlyDataIndication _ -> `EarlyDataIndication
  | `PreSharedKey _        -> `PreSharedKey

let to_server_ext_type = function
  | `Hostname              -> `Hostname
  | `MaxFragmentLength _   -> `MaxFragmentLength
  | `ECPointFormats _      -> `ECPointFormats
  | `SecureRenegotiation _ -> `SecureRenegotiation
  | `UnknownExtension _    -> `UnknownExtension
  | `ExtendedMasterSecret  -> `ExtendedMasterSecret
  | `KeyShare _            -> `KeyShare
  | `EarlyDataIndication   -> `EarlyDataIndication
  | `PreSharedKey _        -> `PreSharedKey

let extension_types t exts = List.(
  exts |> map t
       |> filter @@ function `UnknownExtension -> false | _ -> true
  )

(* a server hello may only contain extensions which are also in the client hello *)
(*  RFC5246, 7.4.7.1
   An extension type MUST NOT appear in the ServerHello unless the same
   extension type appeared in the corresponding ClientHello.  If a
   client receives an extension type in ServerHello that it did not
   request in the associated ClientHello, it MUST abort the handshake
   with an unsupported_extension fatal alert. *)
let server_exts_subset_of_client sexts cexts =
  let (sexts', cexts') =
    (extension_types to_server_ext_type sexts, extension_types to_client_ext_type cexts) in
  List_set.subset sexts' cexts'

module Group = struct
  type t = Packet.named_group
  let compare = Pervasives.compare
end

module GroupSet = Set.Make(Group)

(* Set.of_list appeared only in 4.02, for 4.01 compatibility *)
let of_list xs = List.fold_right GroupSet.add xs GroupSet.empty

let client_hello_valid (ch : client_hello) =
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
  let sig_alg =
    map_find
      ~f:(function `SignatureAlgorithms sa -> Some sa | _ -> None)
      ch.extensions
  and key_share =
    map_find
      ~f:(function `KeyShare ks -> Some ks | _ -> None)
      ch.extensions
  and groups =
    map_find
      ~f:(function `SupportedGroups gs -> Some gs | _ -> None)
      ch.extensions
  in

  let version_good = function
    | Supported TLS_1_2 | TLS_1_X _ -> `Ok
    | Supported TLS_1_3 ->
       ( let good_sig_alg =
           List.exists
             (function
               | (`SHA256, Packet.RSA) (* XXX: remove *)
               | (`SHA256, Packet.RSAPSS)
               | (`SHA384, Packet.RSAPSS)
               | (`SHA512, Packet.RSAPSS) -> true
               | _ -> false)
         in
         match sig_alg with
         | None -> `Error `NoSignatureAlgorithmsExtension
         | Some sig_alg when good_sig_alg sig_alg ->
            ( match key_share, groups with
              | None, _ -> `Error `NoKeyShareExtension
              | _, None -> `Error `NoSupportedGroupExtension
              | Some ks, Some gs ->
                 match
                   List_set.is_proper_set gs,
                   List_set.is_proper_set (List.map fst ks),
                   GroupSet.subset (of_list (List.map fst ks)) (of_list gs)
                 with
                 | true, true, true -> `Ok
                 | false, _, _ -> `Error (`NotSetSupportedGroup gs)
                 | _, false, _ -> `Error (`NotSetKeyShare ks)
                 | _, _, false -> `Error (`NotSubsetKeyShareSupportedGroup (gs, ks)) )
         | Some x -> `Error (`NoGoodSignatureAlgorithms x)
       )
    | SSL_3 | Supported TLS_1_0 | Supported TLS_1_1 ->
      Utils.option
        `Ok
        (fun _ -> `Error `HasSignatureAlgorithmsExtension)
        sig_alg
  in

  match
    not (empty ch.ciphersuites),
    List_set.is_proper_set ch.ciphersuites,
    first_match (filter_map ~f:any_ciphersuite_to_ciphersuite ch.ciphersuites) Config.Ciphers.supported,
    List_set.is_proper_set (extension_types to_client_ext_type ch.extensions)
  with
  | true, true, Some _, true -> version_good ch.client_version
  | false, _ , _, _ -> `Error `EmptyCiphersuites
  | _, false, _, _ -> `Error (`NotSetCiphersuites ch.ciphersuites)
  | _, _, None, _ -> `Error (`NoSupportedCiphersuite ch.ciphersuites)
  | _, _, _, false -> `Error (`NotSetExtension ch.extensions)


let server_hello_valid (sh : server_hello) =
  let open Ciphersuite in

  List_set.is_proper_set (extension_types to_server_ext_type sh.extensions)
  (* TODO:
      - EC stuff must be present if EC ciphersuite chosen
   *)

let (<+>) = Cs.(<+>)

let signature version ?context_string data sig_algs hashes private_key =
  match version with
  | TLS_1_0 | TLS_1_1 ->
    let data = Hash.MD5.digest data <+> Hash.SHA1.digest data in
    let signed = Rsa.PKCS1.sig_encode private_key data in
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
    let cs = X509.Encoding.pkcs1_digest_info_to_cstruct (hash_algo, hash) in
    let sign = Rsa.PKCS1.sig_encode private_key cs in
    Writer.assemble_digitally_signed_1_2 hash_algo Packet.RSA sign
  | TLS_1_3 ->
     (* RSA-PSS is used *)
     (* input is prepended by 64 * 0x20 (to avoid cross-version attacks) *)
     (* input for signature now contains also a context string *)
     let prefix = Cstruct.create 64 in
     Cstruct.memset prefix 0x20 ;
     let ctx =
       let stop = Cstruct.create 1 in
       Cstruct.memset stop 0 ; (* trailing 0 byte *)
       match context_string with
       | None -> stop
       | Some x -> Cstruct.of_string x <+> stop
     in
     ( match sig_algs with
       | None              -> return (`PSS `SHA256)
       | Some client_algos ->
          let pss_client_hashes =
            List.(map fst @@ filter (fun (_, x) -> x = Packet.RSAPSS) client_algos)
          in
          let rsa_client_hashes =
            List.(map fst @@ filter (fun (_, x) -> x = Packet.RSA) client_algos)
          in
          let my_hashes = List.filter (fun x -> List.mem x Config.tls13_hashes) hashes in
          match
            first_match pss_client_hashes my_hashes,
            first_match rsa_client_hashes my_hashes
          with
          | None, None -> fail (`Error (`NoConfiguredHash pss_client_hashes))
          | Some hash, _ -> return (`PSS hash)
          | None, Some hash -> return (`PKCS hash) ) >|= function
     | `PSS hash_algo ->
       let module H = (val (Hash.module_of hash_algo)) in
       let module PSS = Rsa.PSS(H) in
       let data = H.digest data in (* XXX See #407 https://github.com/tlswg/tls13-spec/issues/407 *)
       let to_sign = H.digest (prefix <+> ctx <+> data) in
       let signature = PSS.sign ~key:private_key to_sign in
       Writer.assemble_digitally_signed_1_2 hash_algo Packet.RSAPSS signature
     | `PKCS hash_algo -> (* XXX: remove!!! *)
       let hash = Hash.digest hash_algo data in
       let cs = X509.Encoding.pkcs1_digest_info_to_cstruct (hash_algo, hash) in
       let sign = Rsa.PKCS1.sig_encode private_key cs in
       Writer.assemble_digitally_signed_1_2 hash_algo Packet.RSA sign


let peer_rsa_key = function
  | None -> fail (`Fatal `NoCertificateReceived)
  | Some cert ->
    match X509.public_key cert with
    | `RSA key -> return key
    | _        -> fail (`Fatal `NotRSACertificate)

let verify_digitally_signed version ?context_string hashes data signature_data certificate =
  peer_rsa_key certificate >>= fun pubkey ->

  let decode_signature raw_signature =
    match Rsa.PKCS1.sig_decode pubkey raw_signature with
    | Some signature -> return signature
    | None -> fail (`Fatal `RSASignatureVerificationFailed)
  in

  match version with
  | TLS_1_0 | TLS_1_1 ->
    ( match Reader.parse_digitally_signed data with
      | Ok signature ->
         let compare_hashes should data =
           let computed_sig = Hash.MD5.digest data <+> Hash.SHA1.digest data in
           guard (Cs.equal should computed_sig) (`Fatal `RSASignatureMismatch)
         in
         decode_signature signature >>= fun raw ->
         compare_hashes raw signature_data
      | Error re -> fail (`Fatal (`ReaderError re)) )
  | TLS_1_2 ->
     ( match Reader.parse_digitally_signed_1_2 data with
       | Ok (hash_algo, Packet.RSA, signature) ->
          guard (List.mem hash_algo hashes) (`Error (`NoConfiguredHash hashes)) >>= fun () ->
          let compare_hashes should data =
            match X509.Encoding.pkcs1_digest_info_of_cstruct should with
            | Some (hash_algo', target) when hash_algo = hash_algo' ->
              guard (Crypto.digest_eq hash_algo ~target data) (`Fatal `RSASignatureMismatch)
            | _ -> fail (`Fatal `HashAlgorithmMismatch)
          in
          decode_signature signature >>= fun raw ->
          compare_hashes raw signature_data
        | Ok _ -> fail (`Fatal `NotRSASignature)
        | Error re -> fail (`Fatal (`ReaderError re)) )
    | TLS_1_3 ->
       ( match Reader.parse_digitally_signed_1_2 data with
         | Ok (hash_algo, Packet.RSAPSS, signature) ->
            guard (List.mem hash_algo Config.tls13_hashes) (`Fatal `InvalidMessage) >>= fun () ->
            guard (List.mem hash_algo hashes) (`Error (`NoConfiguredHash hashes)) >>= fun () ->
            let module H = (val (Hash.module_of hash_algo)) in
            let module PSS = Rsa.PSS(H) in
            let data =
              let pre = Cstruct.create 64 in
              Cstruct.memset pre 0x20 ;
              let con =
                let stop = Cstruct.create 1 in
                Cstruct.memset stop 0 ;
                match context_string with
                | None -> stop
                | Some x -> Cstruct.of_string x <+> stop
              in
              let data = H.digest signature_data in
              H.digest (pre <+> con <+> data)
            in
            guard (PSS.verify ~key:pubkey ~signature data) (`Fatal `RSASignatureMismatch)
         | Ok _ -> fail (`Fatal `NotRSASignature)
         | Error re -> fail (`Fatal (`ReaderError re)))

let validate_chain authenticator certificates hostname =
  let authenticate authenticator host certificates =
    match authenticator ?host certificates with
    | `Fail err  -> fail (`Error (`AuthenticationFailure err))
    | `Ok anchor -> return anchor

  and key_size min cs =
    let check c =
      match X509.public_key c with
      | `RSA key when Rsa.pub_bits key >= min -> true
      | _                                     -> false
    in
    guard (List.for_all check cs) (`Fatal `KeyTooSmall)

  and parse_certificates certs =
    let certificates = filter_map ~f:X509.Encoding.parse certs in
    guard (List.length certs = List.length certificates) (`Fatal `BadCertificateChain) >|= fun () ->
    certificates

  in

  (* RFC5246: must be x509v3, take signaturealgorithms into account! *)
  (* RFC2246/4346: is generally x509v3, signing algorithm for certificate _must_ be same as algorithm for certificate key *)
  parse_certificates certificates >>= fun certs ->
  let server = match certs with
    | s::_ -> Some s
    | [] -> None
  in
  match authenticator with
  | None -> return (server, certs, [], None)
  | Some authenticator ->
    authenticate authenticator hostname certs >>= fun anchor ->
    key_size Config.min_rsa_key_size certs >|= fun () ->
    Utils.option
      (server, certs, [], None)
      (fun (chain, anchor) -> (server, certs, chain, Some anchor))
      anchor
