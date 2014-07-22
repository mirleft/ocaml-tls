open Nocrypto

open Utils

open Core
open State
open Handshake_common
open Config

let (<+>) = Cs.(<+>)

let default_client_hello config =
  let host = match config.peer_name with
    | None   -> []
    | Some x -> [Hostname (Some x)]
  in
  let version = max_protocol_version config.protocol_versions in
  let signature_algos = match version with
    | TLS_1_0 | TLS_1_1 -> []
    | TLS_1_2 ->
       let supported = List.map (fun h -> (h, Packet.RSA)) config.hashes in
       [SignatureAlgorithms supported]
  in
  let ch = {
    version      = Supported version ;
    random       = Rng.generate 32 ;
    sessionid    = None ;
    ciphersuites = config.ciphers ;
    extensions   = host @ signature_algos
  }
  in
  ( ch ,
    { server_random = Cstruct.create 0 ;
      client_random = ch.random ;
      client_version = ch.version ;
      cipher = List.hd ch.ciphersuites } ,
   version)

let answer_server_hello state params ch (sh : server_hello) raw log =
  let validate_version requested (lo, _) server_version =
    match
      version_ge requested server_version, server_version >= lo
    with
    | true, true -> return ()
    | _   , _    -> fail Packet.PROTOCOL_VERSION

  and version_compatible reneg prev_version version =
    match reneg with
    | None                               -> return ()
    | Some _ when prev_version = version -> return ()
    | Some _                             -> fail Packet.PROTOCOL_VERSION

  and validate_cipher suites suite =
    match List.mem suite suites with
    | true  -> return ()
    | false -> fail_handshake

  and validate_reneg required reneg data =
    match required, reneg, data with
    | _    , None           , Some x -> assure (Cs.null x)
    | _    , Some (cvd, svd), Some x -> assure (Cs.equal (cvd <+> svd) x)
    | false, _              , _      -> return ()
    | true , _              , _      -> fail_handshake
  in

  let cfg = state.config in
  assure (server_hello_valid sh &&
          server_exts_subset_of_client sh.extensions ch.extensions)
  >>= fun () ->
  validate_version params.client_version state.config.protocol_versions sh.version >>= fun () ->
  version_compatible state.reneg state.version sh.version >>= fun () ->
  validate_cipher cfg.ciphers sh.ciphersuites >>= fun () ->
  let reneg_data = get_secure_renegotiation sh.extensions in
  validate_reneg cfg.secure_reneg state.reneg reneg_data >|= fun () ->

  let machina =
    let cipher = sh.ciphersuites in
    let params = { params with server_random = sh.random ; cipher } in
    Ciphersuite.(match ciphersuite_kex params.cipher with
                 | RSA     -> AwaitCertificate_RSA (params, log @ [raw])
                 | DHE_RSA -> AwaitCertificate_DHE_RSA (params, log @ [raw]))
  in
  ({ state with version = sh.version ; machina = Client machina }, [])

let validate_chain config cipher certificates =
  let open Certificate in

  let parse css =
    match parse_stack css with
    | None       -> fail Packet.BAD_CERTIFICATE
    | Some stack -> return stack

  and authenticate authenticator server_name ((server_cert, _) as stack) =
    match
      X509.Authenticator.authenticate ?host:server_name authenticator stack
    with
    | `Fail SelfSigned         -> fail Packet.UNKNOWN_CA
    | `Fail NoTrustAnchor      -> fail Packet.UNKNOWN_CA
    | `Fail CertificateExpired -> fail Packet.CERTIFICATE_EXPIRED
    | `Fail _                  -> fail Packet.BAD_CERTIFICATE
    | `Ok                      -> return server_cert

  and validate_keytype cert ktype =
    cert_type cert = ktype

  and validate_usage cert usage =
    match cert_usage cert with
    | None        -> true
    | Some usages -> List.mem usage usages

  and validate_ext_usage cert ext_use =
    match cert_extended_usage cert with
    | None            -> true
    | Some ext_usages -> List.mem ext_use ext_usages || List.mem `Any ext_usages
  in

  let key_size min cs =
    let check c =
      let open Asn_grammars in
      ( match Certificate.(asn_of_cert c).tbs_cert.pk_info with
        | PK.RSA key when RSA.pub_bits key >= min -> true
        | _                                       -> false )
    in
    guard (List.for_all check cs) Packet.INSUFFICIENT_SECURITY
  in

  let host = match config.peer_name with
    | None   -> None
    | Some x -> Some (`Wildcard x)
  in

  (* RFC5246: must be x509v3, take signaturealgorithms into account! *)
  (* RFC2246/4346: is generally x509v3, signing algorithm for certificate _must_ be same as algorithm for certificate key *)

  match config.authenticator with
  | None -> parse certificates >|= fun (server, _) ->
            server
  | Some authenticator ->
      parse certificates >>= fun (s, xs) ->
      key_size Config.min_rsa_key_size (s :: xs) >>= fun () ->
      authenticate authenticator host (s, xs) >>= fun cert ->
      let keytype, usage =
        Ciphersuite.(o required_keytype_and_usage ciphersuite_kex cipher)
      in
      guard (validate_keytype cert keytype &&
             validate_usage cert usage &&
             validate_ext_usage cert `Server_auth)
            Packet.BAD_CERTIFICATE >|= fun () -> cert

let peer_rsa_key cert =
  let open Asn_grammars in
  match Certificate.(asn_of_cert cert).tbs_cert.pk_info with
  | PK.RSA key -> return key
  | _          -> fail_handshake

let answer_certificate_RSA state params cs raw log =
  validate_chain state.config params.cipher cs >>= fun cert ->
  ( match params.client_version with
    | Supported v -> return v
    | _           -> fail_handshake ) >>= fun v ->
  let ver = Writer.assemble_protocol_version v in
  let premaster = ver <+> Rng.generate 46 in
  peer_rsa_key cert >|= fun pubkey ->
  let kex = RSA.PKCS1.encrypt pubkey premaster in

  let machina = AwaitServerHelloDone (params, kex, premaster, log @ [raw]) in
  ({ state with machina = Client machina }, [])

let answer_certificate_DHE_RSA state params cs raw log =
  validate_chain state.config params.cipher cs >|= fun cert ->
  let machina = AwaitServerKeyExchange_DHE_RSA (params, cert, log @ [raw]) in
  ({ state with machina = Client machina }, [])


let answer_server_key_exchange_DHE_RSA state params cert kex raw log =
  let open Reader in
  let dh_params kex =
    match parse_dh_parameters kex with
    | Or_error.Ok data -> return data
    | Or_error.Error _ -> fail_handshake

  and signature_verifier version data =
    match version with
    | TLS_1_0 | TLS_1_1 ->
        ( match parse_digitally_signed data with
          | Or_error.Ok signature ->
             let compare_hashes should data =
               let computed_sig = Hash.(MD5.digest data <+> SHA1.digest data) in
               assure (Cs.equal should computed_sig)
             in
             return (signature, compare_hashes)
          | Or_error.Error _      -> fail_handshake )
    | TLS_1_2 ->
       ( match parse_digitally_signed_1_2 data with
         | Or_error.Ok (hash_algo, Packet.RSA, signature) ->
            let compare_hashes should data =
              match Crypto.pkcs1_digest_info_of_cstruct should with
              | Some (hash_algo', target) when hash_algo = hash_algo' ->
                 ( match Crypto.hash_eq hash_algo ~target data with
                   | true  -> return ()
                   | false -> fail_handshake )
              | _ -> fail_handshake
            in
            return (signature, compare_hashes)
         | _ -> fail_handshake )

  and signature pubkey raw_signature =
    match RSA.PKCS1.verify pubkey raw_signature with
    | Some signature -> return signature
    | None -> fail_handshake

  in

  dh_params kex >>= fun (dh_params, raw_dh_params, leftover) ->
  signature_verifier state.version leftover >>= fun (raw_signature, verifier) ->
  peer_rsa_key cert >>= fun pubkey ->
  signature pubkey raw_signature >>= fun signature ->
  let sigdata = params.client_random <+> params.server_random <+> raw_dh_params in
  verifier signature sigdata >>= fun () ->
  let group, shared = Crypto.dh_params_unpack dh_params in
  guard (DH.apparent_bit_size group >= Config.min_dh_size) Packet.INSUFFICIENT_SECURITY
  >>= fun () ->

  let secret, kex = DH.gen_secret group in
  match Crypto.dh_shared group secret shared with
  | None     -> fail Packet.INSUFFICIENT_SECURITY
  | Some pms -> let machina = AwaitServerHelloDone (params, kex, pms, log @ [raw]) in
                return ({ state with machina = Client machina }, [])

let answer_server_hello_done state params kex premaster raw log =
  let kex = ClientKeyExchange kex in
  let ckex = Writer.assemble_handshake kex in
  let (ccst, ccs) = change_cipher_spec in
  let client_ctx, server_ctx, master_secret =
    Handshake_crypto.initialise_crypto_ctx state.version params premaster in
  let to_fin = log @ [raw; ckex] in
  let checksum = Handshake_crypto.finished state.version master_secret "client finished" to_fin in
  let fin = Finished checksum in
  let raw_fin = Writer.assemble_handshake fin in
  let ps = to_fin @ [raw_fin] in
  let machina = AwaitServerChangeCipherSpec (server_ctx, checksum, master_secret, ps)
  in
  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake kex;
  Tracing.cs ~tag:"change-cipher-spec-out" ccs ;
  Tracing.cs ~tag:"master-secret" master_secret;
  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake fin;

  return ({ state with machina = Client machina },
          [`Record (Packet.HANDSHAKE, ckex);
           `Record (ccst, ccs);
           `Change_enc (Some client_ctx);
           `Record (Packet.HANDSHAKE, raw_fin)])

let answer_server_finished state client_verify master_secret fin log =
  let computed = Handshake_crypto.finished state.version master_secret "server finished" log in
  assure (Cs.equal computed fin && Cs.null state.hs_fragment)
  >|= fun () ->
  let machina = Established in
  let reneg = Some (client_verify, computed) in
  ({ state with machina = Client machina ; reneg }, [])

let answer_hello_request state =
  let get_reneg_data optdata =
    match optdata with
    | None          -> fail_handshake
    | Some (cvd, _) -> return (SecureRenegotiation cvd)

  and produce_client_hello config exts =
     let dch, params, _ = default_client_hello config in
     let ch = { dch with
                  extensions = exts @ dch.extensions } in
     let raw = Writer.assemble_handshake (ClientHello ch) in
     let machina = AwaitServerHello (ch, params, [raw]) in
     Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake (ClientHello ch) ;
     ({ state with machina = Client machina }, [`Record (Packet.HANDSHAKE, raw)])

  in
  if state.config.use_reneg then
    get_reneg_data state.reneg >|= fun ext ->
    produce_client_hello state.config [ext]
  else
    let no_reneg = Writer.assemble_alert ~level:Packet.WARNING Packet.NO_RENEGOTIATION in
    return (state, [`Record (Packet.ALERT, no_reneg)])

let handle_change_cipher_spec cs state packet =
  let open Reader in
  match parse_change_cipher_spec packet, cs with
  | Or_error.Ok (), AwaitServerChangeCipherSpec (server_ctx, client_verify, ms, log) ->
     assure (Cs.null state.hs_fragment) >>= fun () ->
     let machina = AwaitServerFinished (client_verify, ms, log) in
     Tracing.cs ~tag:"change-cipher-spec-in" packet ;
     return ({ state with machina = Client machina }, [], `Change_dec (Some server_ctx))
  | _ ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_handshake cs hs buf =
  let open Reader in
  match parse_handshake buf with
  | Or_error.Ok handshake ->
     Tracing.sexpf ~tag:"handshake-in" ~f:sexp_of_tls_handshake handshake ;
     ( match cs, handshake with
       | AwaitServerHello (ch, params, log), ServerHello sh ->
          answer_server_hello hs params ch sh buf log
       | AwaitCertificate_RSA (params, log), Certificate cs ->
          answer_certificate_RSA hs params cs buf log
       | AwaitCertificate_DHE_RSA (params, log), Certificate cs ->
          answer_certificate_DHE_RSA hs params cs buf log
       | AwaitServerKeyExchange_DHE_RSA (params, cert, log), ServerKeyExchange kex ->
          answer_server_key_exchange_DHE_RSA hs params cert kex buf log
       | AwaitServerHelloDone (params, kex, pms, log), ServerHelloDone ->
          answer_server_hello_done hs params kex pms buf log
       | AwaitServerFinished (client_verify, master, log), Finished fin ->
          answer_server_finished hs client_verify master fin log
       | Established, HelloRequest ->
          answer_hello_request hs
       | _, _ -> fail_handshake )
  | Or_error.Error _ -> fail Packet.UNEXPECTED_MESSAGE

