open Core
open State

open Mirage_crypto

let src = Logs.Src.create "handshake" ~doc:"TLS handshake"
module Log = (val Logs.src_log src : Logs.LOG)

let trace_cipher cipher =
  Tracing.debug (fun m -> m "%a" Ciphersuite.pp_ciphersuite cipher)

let empty = function [] -> true | _ -> false

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

let hostname (h : client_hello) : [ `host ] Domain_name.t option =
  Utils.map_find ~f:(function `Hostname s -> Some s | _ -> None) h.extensions

let groups (h : client_hello) =
  match Utils.map_find ~f:(function `SupportedGroups g -> Some g | _ -> None) h.extensions with
  | Some xs ->
    List.fold_left (fun acc g ->
        match named_group_to_group g with Some g -> g :: acc | _ -> acc)
      [] xs
  | None -> []

let rec find_matching host certs =
  match certs with
  | (s::_, _) as chain ::xs ->
    if X509.Certificate.supports_hostname s host then
      Some chain
    else
      find_matching host xs
  | _::xs -> find_matching host xs (* this should never happen! *)
  | [] -> None

let agreed_cert certs ?f ?signature_algorithms hostname =
  let match_host ?default host certs =
     match find_matching host certs with
     | Some x -> Ok x
     | None   ->
       Option.to_result
         ~none:(`Error (`NoMatchingCertificateFound (Domain_name.to_string host)))
         default
  in
  let filter = function
    | ([], _) -> false (* cannot happen, TODO: adapt types to avoid this case *)
    | (s :: _, _) ->
      match f with
      | None -> true
      | Some f -> f s
  in
  let filter_sigalg c =
    match signature_algorithms with
    | None -> true
    | Some s -> List.exists (pk_matches_sa (snd c)) s
  in
  match certs, hostname with
  | `None, _ -> Error (`Error `NoCertificateConfigured)
  | `Single c, _ ->
    if filter c && filter_sigalg c then Ok c else Error (`Error `CouldntSelectCertificate)
  | `Multiple_default (c, _), None ->
    if filter c && filter_sigalg c then Ok c else Error (`Error `CouldntSelectCertificate)
  | `Multiple_default (c, cs), Some h ->
    let default = if filter c && filter_sigalg c then Some c else None in
    begin match default, List.filter (fun c -> filter c && filter_sigalg c) cs with
      | Some d, cs -> match_host ~default:d h cs
      | None, c :: cs -> match_host ~default:c h (c::cs)
      | None, [] -> Error (`Error `CouldntSelectCertificate)
    end
  | `Multiple cs, None ->
    begin match List.filter (fun c -> filter c && filter_sigalg c) cs with
      | cert :: _ -> Ok cert
      | _ -> Error (`Error `CouldntSelectCertificate)
    end
  | `Multiple cs, Some h ->
    match List.filter (fun c -> filter c && filter_sigalg c) cs with
    | [ cert ] -> Ok cert
    | c :: cs -> match_host ~default:c h (c :: cs)
    | [] -> Error (`Error `CouldntSelectCertificate)

let get_secure_renegotiation exts =
  Utils.map_find
    exts
    ~f:(function `SecureRenegotiation data -> Some data | _ -> None)

let get_alpn_protocols (ch : client_hello) =
  Utils.map_find ~f:(function `ALPN protocols -> Some protocols | _ -> None) ch.extensions

let alpn_protocol config ch =
  match config.Config.alpn_protocols, get_alpn_protocols ch with
  | _, None | [], _ -> Ok None
  | configured, Some client -> match Utils.first_match client configured with
    | Some proto -> Ok (Some proto)
    | None ->
      (* RFC7301 Section 3.2:
         In the event that the server supports no protocols that the client
         advertises, then the server SHALL respond with a fatal
         "no_application_protocol" alert. *)
      Error (`Fatal `NoApplicationProtocol)

let get_alpn_protocol (sh : server_hello) =
  Utils.map_find ~f:(function `ALPN protocol -> Some protocol | _ -> None) sh.extensions

let empty_common_session_data = {
  server_random          = Cstruct.create 0 ;
  client_random          = Cstruct.create 0 ;
  peer_certificate_chain = [] ;
  peer_certificate       = None ;
  trust_anchor           = None ;
  received_certificates  = [] ;
  own_certificate        = [] ;
  own_private_key        = None ;
  own_name               = None ;
  client_auth            = false ;
  master_secret          = Cstruct.empty ;
  alpn_protocol          = None ;
}

let empty_session = {
  common_session_data = empty_common_session_data ;
  client_version      = `TLS_1_2 ;
  ciphersuite         = `DHE_RSA_WITH_AES_256_CBC_SHA ;
  group               = Some `FFDHE2048 ;
  renegotiation       = Cstruct.(empty, empty) ;
  session_id          = Cstruct.empty ;
  extended_ms         = false ;
}

let empty_session13 cipher = {
  common_session_data13 = empty_common_session_data ;
  ciphersuite13         = cipher ;
  master_secret         = Handshake_crypto13.empty cipher ;
  resumption_secret     = Cstruct.empty ;
  state                 = `Established ;
  resumed               = false ;
  client_app_secret     = Cstruct.empty ;
  server_app_secret     = Cstruct.empty ;
}

let common_session_data_of_epoch (epoch : epoch_data) common_session_data =
  {
    common_session_data with
    peer_certificate = epoch.peer_certificate ;
    trust_anchor = epoch.trust_anchor ;
    own_certificate = epoch.own_certificate ;
    own_private_key = epoch.own_private_key ;
    received_certificates = epoch.received_certificates ;
    peer_certificate_chain = epoch.peer_certificate_chain ;
    master_secret = epoch.master_secret ;
    own_name = epoch.own_name ;
    alpn_protocol = epoch.alpn_protocol ;
  }

let session_of_epoch (epoch : epoch_data) : session_data =
  let empty = empty_session in
  let common_session_data = common_session_data_of_epoch epoch empty.common_session_data in
  { empty with
    common_session_data ;
    ciphersuite = epoch.ciphersuite ;
    session_id = epoch.session_id ;
    extended_ms = epoch.extended_ms ;
  }

let session13_of_epoch cipher (epoch : epoch_data) : session_data13 =
  let empty = empty_session13 cipher in
  let common_session_data13 = common_session_data_of_epoch epoch empty.common_session_data13 in
  { empty with
    common_session_data13 ;
    ciphersuite13 = cipher ;
    state = epoch.state ;
  }

let supported_protocol_version (min, max) v =
  if compare_tls_version min v > 0 then
    None
  else if compare_tls_version v max > 0 then
    None
  else
    Some v

let to_client_ext_type = function
  | `Hostname _            -> `Hostname
  | `MaxFragmentLength _   -> `MaxFragmentLength
  | `SupportedGroups _     -> `SupportedGroups
  | `ECPointFormats        -> `ECPointFormats
  | `SecureRenegotiation _ -> `SecureRenegotiation
  | `Padding _             -> `Padding
  | `SignatureAlgorithms _ -> `SignatureAlgorithms
  | `UnknownExtension _    -> `UnknownExtension
  | `ExtendedMasterSecret  -> `ExtendedMasterSecret
  | `ALPN _                -> `ALPN
  | `KeyShare _            -> `KeyShare
  | `EarlyDataIndication   -> `EarlyDataIndication
  | `PreSharedKeys _       -> `PreSharedKey
  | `Draft _               -> `Draft
  | `SupportedVersions _   -> `SupportedVersion
  | `PostHandshakeAuthentication -> `PostHandshakeAuthentication
  | `Cookie _              -> `Cookie
  | `PskKeyExchangeModes _ -> `PskKeyExchangeMode

let to_server_ext_type = function
  | `Hostname              -> `Hostname
  | `MaxFragmentLength _   -> `MaxFragmentLength
  | `ECPointFormats        -> `ECPointFormats
  | `SecureRenegotiation _ -> `SecureRenegotiation
  | `UnknownExtension _    -> `UnknownExtension
  | `ExtendedMasterSecret  -> `ExtendedMasterSecret
  | `ALPN _                -> `ALPN
  | `KeyShare _            -> `KeyShare
  | `EarlyDataIndication   -> `EarlyDataIndication
  | `PreSharedKey _        -> `PreSharedKey
  | `Draft _               -> `Draft
  | `SelectedVersion _     -> `SupportedVersion

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
  Utils.List_set.subset sexts' (`Cookie :: cexts')

module Group = struct
  type t = Packet.named_group
  let compare = Stdlib.compare
end

module GroupSet = Set.Make(Group)

(* Set.of_list appeared only in 4.02, for 4.01 compatibility *)
let of_list xs = List.fold_right GroupSet.add xs GroupSet.empty

let client_hello_valid version (ch : client_hello) =
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
    Utils.map_find
      ~f:(function `SignatureAlgorithms sa -> Some sa | _ -> None)
      ch.extensions
  and key_share =
    Utils.map_find
      ~f:(function `KeyShare ks -> Some ks | _ -> None)
      ch.extensions
  and groups =
    Utils.map_find
      ~f:(function `SupportedGroups gs -> Some gs | _ -> None)
      ch.extensions
  in

  let version_good = match version with
    | `TLS_1_2 | `TLS_1_X _ -> Ok ()
    | `TLS_1_3 ->
      ( let good_sig_alg =
          List.exists (fun sa -> List.mem sa Config.supported_signature_algorithms)
        in
        match sig_alg with
        | None -> Error `NoSignatureAlgorithmsExtension
        | Some sig_alg when good_sig_alg sig_alg ->
          ( match key_share, groups with
            | None, _ -> Error `NoKeyShareExtension
            | _, None -> Error `NoSupportedGroupExtension
            | Some ks, Some gs ->
              match
                Utils.List_set.is_proper_set gs,
                Utils.List_set.is_proper_set (List.map fst ks),
                GroupSet.subset (of_list (List.map fst ks)) (of_list gs)
              with
              | true, true, true -> Ok ()
              | false, _, _ -> Error (`NotSetSupportedGroup gs)
              | _, false, _ -> Error (`NotSetKeyShare ks)
              | _, _, false -> Error (`NotSubsetKeyShareSupportedGroup (gs, ks)) )
        | Some x -> Error (`NoGoodSignatureAlgorithms x)
      )
    | `SSL_3 | `TLS_1_0 | `TLS_1_1 -> Ok ()
  in

  let share_ciphers =
    match
      Utils.first_match (List.filter_map Ciphersuite.any_ciphersuite_to_ciphersuite ch.ciphersuites) Config.Ciphers.supported
    with
    | None -> false
    | Some _ -> true
  in
  match
    not (empty ch.ciphersuites),
    Utils.List_set.is_proper_set ch.ciphersuites,
    share_ciphers,
    Utils.List_set.is_proper_set (extension_types to_client_ext_type ch.extensions)
  with
  | true, _, true, true -> version_good
  | false, _ , _, _ -> Error `EmptyCiphersuites
  (*  | _, false, _, _ -> Error (`NotSetCiphersuites ch.ciphersuites) *)
  | _, _, false, _ -> Error (`NoSupportedCiphersuite ch.ciphersuites)
  | _, _, _, false -> Error (`NotSetExtension ch.extensions)


let server_hello_valid (sh : server_hello) =
  (* let open Ciphersuite in *)
  Utils.List_set.is_proper_set (extension_types to_server_ext_type sh.extensions)
  (* TODO:
      - EC stuff must be present if EC ciphersuite chosen
   *)

let to_sign_1_3 context_string =
  (* input is prepended by 64 * 0x20 (to avoid cross-version attacks) *)
  (* input for signature now contains also a context string *)
  let prefix = Cstruct.create 64 in
  Cstruct.memset prefix 0x20 ;
  let ctx =
    let stop = Cstruct.create 1 (* trailing 0 byte *) in
    match context_string with
    | None -> stop
    | Some x -> Cstruct.of_string x <+> stop
  in
  prefix <+> ctx

let signature version ?context_string data client_sig_algs signature_algorithms (private_key : X509.Private_key.t) =
  match version with
  | `TLS_1_0 | `TLS_1_1 ->
    let* signed =
      match private_key with
      | `RSA key ->
        begin try
            let data = Hash.MD5.digest data <+> Hash.SHA1.digest data in
            Ok (Mirage_crypto_pk.Rsa.PKCS1.sig_encode ~key data)
          with Mirage_crypto_pk.Rsa.Insufficient_key ->
            Error (`Fatal `KeyTooSmall)
        end
      | k ->
        (* not passing ~scheme: only non-RSA keys sig scheme is trivial *)
        Result.map_error
          (function `Msg m -> `Fatal (`SigningFailed m))
          (X509.Private_key.sign `SHA1 k (`Message data))
    in
    Ok (Writer.assemble_digitally_signed signed)
  | `TLS_1_2 ->
    let* sig_alg =
      match client_sig_algs with
      | None ->
        Ok (match private_key with
            | `RSA _ -> `RSA_PKCS1_SHA1
            | `ED25519 _ -> `ED25519
            | _ -> `ECDSA_SECP256R1_SHA1)
      | Some client_algos ->
        Option.to_result
          ~none:(`Error (`NoConfiguredSignatureAlgorithm client_algos))
          (Utils.first_match client_algos (List.filter (pk_matches_sa private_key) signature_algorithms))
    in
    let scheme = signature_scheme_of_signature_algorithm sig_alg
    and hash = hash_of_signature_algorithm sig_alg
    in
    let* signature =
      Result.map_error (function `Msg m -> `Fatal (`SigningFailed m))
        (X509.Private_key.sign hash ~scheme private_key (`Message data))
    in
    Ok (Writer.assemble_digitally_signed_1_2 sig_alg signature)
  | `TLS_1_3 ->
    let to_sign =
      let prefix = to_sign_1_3 context_string in
      prefix <+> data
    in
    let* sig_alg =
      let* client_algos =
        (* 8446 4.2.3 "client MUST send signatureAlgorithms" *)
        Option.to_result
          ~none:(`Error (`NoConfiguredSignatureAlgorithm []))
          client_sig_algs
      in
      let sa = List.filter tls13_sigalg signature_algorithms in
      let sa = List.filter (pk_matches_sa private_key) sa in
      Option.to_result
        ~none:(`Error (`NoConfiguredSignatureAlgorithm client_algos))
        (Utils.first_match client_algos sa)
    in
    let scheme = signature_scheme_of_signature_algorithm sig_alg
    and hash = hash_of_signature_algorithm sig_alg
    in
    let* signature =
      Result.map_error (function `Msg m -> `Fatal (`SigningFailed m))
        (X509.Private_key.sign hash ~scheme private_key (`Message to_sign))
    in
    Ok (Writer.assemble_digitally_signed_1_2 sig_alg signature)

let peer_key = function
  | None -> Error (`Fatal `NoCertificateReceived)
  | Some cert -> Ok (X509.Certificate.public_key cert)

let verify_digitally_signed version ?context_string sig_algs data signature_data certificate =
  let* pubkey = peer_key certificate in
  match version with
  | `TLS_1_0 | `TLS_1_1 ->
    let* signature = map_reader_error (Reader.parse_digitally_signed data) in
    begin match pubkey with
      | `RSA key ->
        let* raw =
          Option.to_result
            ~none:(`Fatal (`SignatureVerificationFailed "couldn't decode PKCS1"))
            (Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key signature)
        in
        let computed =
          Hash.(MD5.digest signature_data <+> SHA1.digest signature_data)
        in
        guard (Cstruct.equal raw computed)
          (`Fatal (`SignatureVerificationFailed "RSA PKCS1 raw <> computed"))
      | key ->
        Result.map_error
          (function `Msg m -> `Fatal (`SignatureVerificationFailed m))
          (X509.Public_key.verify `SHA1 ~signature key (`Message signature_data))
    end
  | `TLS_1_2 ->
    let* sig_alg, signature =
      map_reader_error (Reader.parse_digitally_signed_1_2 data)
    in
    let* () =
      guard (List.mem sig_alg sig_algs)
        (`Error (`NoConfiguredSignatureAlgorithm sig_algs))
    in
    let hash = hash_of_signature_algorithm sig_alg
    and scheme = signature_scheme_of_signature_algorithm sig_alg
    in
    Result.map_error
      (function `Msg m -> `Fatal (`SignatureVerificationFailed m))
      (X509.Public_key.verify hash ~scheme ~signature pubkey (`Message signature_data))
  | `TLS_1_3 ->
    let* sig_alg, signature =
      map_reader_error (Reader.parse_digitally_signed_1_2 data)
    in
    let* () =
      guard (List.mem sig_alg sig_algs)
        (`Error (`NoConfiguredSignatureAlgorithm sig_algs))
    in
    let hash = hash_of_signature_algorithm sig_alg
    and scheme = signature_scheme_of_signature_algorithm sig_alg
    and data =
      let prefix = to_sign_1_3 context_string in
      prefix <+> signature_data
    in
    Result.map_error
      (function `Msg m -> `Fatal (`SignatureVerificationFailed m))
      (X509.Public_key.verify hash ~scheme ~signature pubkey (`Message data))

let validate_chain authenticator certificates ip hostname =
  let authenticate authenticator host certificates =
    Result.map_error
      (fun err -> `Error (`AuthenticationFailure err))
      (authenticator ?ip ~host certificates)

  and key_size min cs =
    let check c =
      match X509.Certificate.public_key c with
      | `RSA key -> Mirage_crypto_pk.Rsa.pub_bits key >= min
      | _ -> true
    in
    guard (List.for_all check cs) (`Fatal `KeyTooSmall)

  and parse_certificates certs =
    let certificates =
      let f cs =
        match X509.Certificate.decode_der cs with
        | Ok c -> Some c
        | Error `Msg msg ->
          Log.warn (fun m -> m "cannot decode certificate %s:@.%a" msg
                       Cstruct.hexdump_pp cs);
          None
      in
      List.filter_map f certs
    in
    let* () =
      guard (List.length certs = List.length certificates)
        (`Fatal `BadCertificateChain)
    in
    Ok certificates
  in

  (* RFC5246: must be x509v3, take signaturealgorithms into account! *)
  (* RFC2246/4346: is generally x509v3, signing algorithm for certificate _must_ be same as algorithm for certificate key *)
  let* certs = parse_certificates certificates in
  let server = match certs with
    | s::_ -> Some s
    | [] -> None
  in
  match authenticator with
  | None -> Ok (server, certs, [], None)
  | Some authenticator ->
    let* anchor = authenticate authenticator hostname certs in
    let* () = key_size Config.min_rsa_key_size certs in
    Ok (Option.fold ~none:(server, certs, [], None)
          ~some:(fun (chain, anchor) -> (server, certs, chain, Some anchor))
          anchor)

let output_key_update ~request state =
  let hs = state.handshake in
  match hs.session with
  | `TLS13 session :: _ ->
    let* session', encryptor =
      match hs.machina with
      | Client13 Established13 ->
        let client_app_secret, client_ctx =
          Handshake_crypto13.app_secret_n_1
            session.master_secret session.client_app_secret
        in
        Ok ({ session with client_app_secret }, client_ctx)
      | Server13 Established13 ->
        let server_app_secret, server_ctx =
          Handshake_crypto13.app_secret_n_1
            session.master_secret session.server_app_secret
        in
        Ok ({ session with server_app_secret }, server_ctx)
      | _ -> Error (`Fatal `InvalidSession)
    in
    let handshake = { hs with session = `TLS13 session' :: hs.session } in
    let ku =
      let p =
        Packet.(if request then UPDATE_REQUESTED else UPDATE_NOT_REQUESTED)
      in
      KeyUpdate p
    in
    let out = Writer.assemble_handshake ku in
    Ok ({ state with encryptor = Some encryptor ; handshake },
        (Packet.HANDSHAKE, out))
  | _ -> Error (`Fatal `InvalidSession)
