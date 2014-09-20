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
  let ciphers =
    let cs = config.ciphers in
    match version with
    | TLS_1_0 | TLS_1_1 -> List.filter (o not Ciphersuite.ciphersuite_tls12_only) cs
    | TLS_1_2           -> cs
  in
  let ch = {
    version      = Supported version ;
    random       = Rng.generate 32 ;
    sessionid    = None ;
    ciphersuites = List.map Ciphersuite.ciphersuite_to_any_ciphersuite ciphers ;
    extensions   = host @ signature_algos
  }
  in
  (ch , version)

let validate_cipher suites suite = assure (List.mem suite suites)

let answer_server_hello state ch (sh : server_hello) raw log =
  let validate_version requested (lo, _) server_version =
    guard (version_ge requested server_version && server_version >= lo)
          Packet.PROTOCOL_VERSION

  and validate_reneg required data =
    match required, data with
    | _    , Some x -> assure (Cs.null x)
    | false, _      -> return ()
    | true , _      -> fail_handshake
  in

  let cfg = state.config in
  assure (server_hello_valid sh &&
          server_exts_subset_of_client sh.extensions ch.extensions)
  >>= fun () ->
  validate_version ch.version state.config.protocol_versions sh.version >>= fun () ->
  validate_cipher cfg.ciphers sh.ciphersuites >>= fun () ->
  validate_reneg cfg.secure_reneg (get_secure_renegotiation sh.extensions) >|= fun () ->

  let machina =
    let cipher = sh.ciphersuites in
    let session =
      { empty_session with
        client_random    = ch.random ;
        client_version   = ch.version ;
        server_random    = sh.random ;
        ciphersuite      = cipher ;
    }
    in
    Ciphersuite.(match ciphersuite_kex cipher with
                 | RSA     -> AwaitCertificate_RSA (session, log @ [raw])
                 | DHE_RSA -> AwaitCertificate_DHE_RSA (session, log @ [raw]))
  in
  ({ state with protocol_version = sh.version ; machina = Client machina }, [])

let answer_server_hello_renegotiate state session ch (sh : server_hello) raw log =
  let validate_reneg required reneg data =
    match required, reneg, data with
    | _    , (cvd, svd), Some x -> assure (Cs.equal (cvd <+> svd) x)
    | false, _         , _      -> return ()
    | true , _         , _      -> fail_handshake
  in

  let cfg = state.config in
  assure (server_hello_valid sh &&
          server_exts_subset_of_client sh.extensions ch.extensions)
  >>= fun () ->
  guard (state.protocol_version = sh.version) Packet.PROTOCOL_VERSION >>= fun () ->
  validate_cipher cfg.ciphers sh.ciphersuites >>= fun () ->
  let theirs = get_secure_renegotiation sh.extensions in
  validate_reneg cfg.secure_reneg session.renegotiation theirs >|= fun () ->

  let machina =
    let cipher = sh.ciphersuites in
    let session = { empty_session with
      ciphersuite      = cipher ;
      server_random    = sh.random ;
      client_random    = ch.random ;
      client_version   = ch.version
    } in
    Ciphersuite.(match ciphersuite_kex cipher with
                 | RSA     -> AwaitCertificate_RSA (session, log @ [raw])
                 | DHE_RSA -> AwaitCertificate_DHE_RSA (session, log @ [raw]))
  in
  ({ state with machina = Client machina }, [])


let validate_chain config session certificates =
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
    | `Ok anchor               -> return anchor

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

  and key_size min cs =
    let check c =
      let open Asn_grammars in
      ( match Certificate.(asn_of_cert c).tbs_cert.pk_info with
        | PK.RSA key when Rsa.pub_bits key >= min -> true
        | _                                       -> false )
    in
    guard (List.for_all check cs) Packet.INSUFFICIENT_SECURITY

  and host = match config.peer_name with
    | None   -> None
    | Some x -> Some (`Wildcard x)
  in

  (* RFC5246: must be x509v3, take signaturealgorithms into account! *)
  (* RFC2246/4346: is generally x509v3, signing algorithm for certificate _must_ be same as algorithm for certificate key *)

  match config.authenticator with
  | None -> parse certificates >|= fun (s, xs) ->
            (s, { session with peer_certificate = s :: xs })
  | Some authenticator ->
      parse certificates >>= fun (s, xs) ->
      key_size Config.min_rsa_key_size (s :: xs) >>= fun () ->
      authenticate authenticator host (s, xs) >>= fun anchor ->
      let keytype, usage =
        Ciphersuite.(o required_keytype_and_usage ciphersuite_kex session.ciphersuite)
      in
      guard (validate_keytype s keytype &&
             validate_usage s usage &&
             validate_ext_usage s `Server_auth)
            Packet.BAD_CERTIFICATE >|= fun () ->
      (s, { session with peer_certificate = s :: xs ; trust_anchor = Some anchor })

let peer_rsa_key cert =
  let open Asn_grammars in
  match Certificate.(asn_of_cert cert).tbs_cert.pk_info with
  | PK.RSA key -> return key
  | _          -> fail_handshake

let answer_certificate_RSA state session cs raw log =
  validate_chain state.config session cs >>= fun (cert, session) ->
  ( match session.client_version with
    | Supported v -> return v
    | _           -> fail_handshake ) >>= fun v ->
  let ver = Writer.assemble_protocol_version v in
  let premaster = ver <+> Rng.generate 46 in
  peer_rsa_key cert >|= fun pubkey ->
  let kex = Rsa.PKCS1.encrypt pubkey premaster
  in

  let machina = AwaitServerHelloDone (session, kex, premaster, log @ [raw]) in
  ({ state with machina = Client machina }, [])

let answer_certificate_DHE_RSA state session cs raw log =
  validate_chain state.config session cs >|= fun (_, session) ->
  let machina = AwaitServerKeyExchange_DHE_RSA (session, log @ [raw]) in
  ({ state with machina = Client machina }, [])

let answer_server_key_exchange_DHE_RSA state session kex raw log =
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
              match Asn_grammars.pkcs1_digest_info_of_cstruct should with
              | Some (hash_algo', target) when hash_algo = hash_algo' ->
                 ( match Crypto.digest_eq hash_algo ~target data with
                   | true  -> return ()
                   | false -> fail_handshake )
              | _ -> fail_handshake
            in
            return (signature, compare_hashes)
         | _ -> fail_handshake )

  and signature pubkey raw_signature =
    match Rsa.PKCS1.verify pubkey raw_signature with
    | Some signature -> return signature
    | None -> fail_handshake

  in

  dh_params kex >>= fun (dh_params, raw_dh_params, leftover) ->
  signature_verifier state.protocol_version leftover >>= fun (raw_signature, verifier) ->
  (match session.peer_certificate with
   | cert :: _ -> peer_rsa_key cert
   | []        -> fail_handshake ) >>= fun pubkey ->
  signature pubkey raw_signature >>= fun signature ->
  let sigdata = session.client_random <+> session.server_random <+> raw_dh_params in
  verifier signature sigdata >>= fun () ->
  let group, shared = Crypto.dh_params_unpack dh_params in
  guard (Dh.apparent_bit_size group >= Config.min_dh_size) Packet.INSUFFICIENT_SECURITY
  >>= fun () ->

  let secret, kex = Dh.gen_secret group in
  match Crypto.dh_shared group secret shared with
  | None     -> fail Packet.INSUFFICIENT_SECURITY
  | Some pms -> let machina = AwaitServerHelloDone (session, kex, pms, log @ [raw]) in
                return ({ state with machina = Client machina }, [])

let answer_server_hello_done state session kex premaster raw log =
  let kex = ClientKeyExchange kex in
  let ckex = Writer.assemble_handshake kex in
  let client_ctx, server_ctx, master_secret =
    Handshake_crypto.initialise_crypto_ctx state.protocol_version session premaster in
  let to_fin = log @ [raw; ckex] in
  let checksum = Handshake_crypto.finished state.protocol_version master_secret "client finished" to_fin in
  let fin = Finished checksum in
  let raw_fin = Writer.assemble_handshake fin in
  let ps = to_fin @ [raw_fin] in

  let session = { session with master_secret = master_secret } in
  let machina = AwaitServerChangeCipherSpec (session, server_ctx, checksum, ps)
  and ccst, ccs = change_cipher_spec in

  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake kex;
  Tracing.cs ~tag:"change-cipher-spec-out" ccs ;
  Tracing.cs ~tag:"master-secret" master_secret;
  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake fin;

  return ({ state with machina = Client machina },
          [`Record (Packet.HANDSHAKE, ckex);
           `Record (ccst, ccs);
           `Change_enc (Some client_ctx);
           `Record (Packet.HANDSHAKE, raw_fin)])

let answer_server_finished state session client_verify fin log =
  let computed =
    Handshake_crypto.finished state.protocol_version session.master_secret "server finished" log
  in
  assure (Cs.equal computed fin && Cs.null state.hs_fragment)
  >|= fun () ->
  let machina = Established
  and session = { session with renegotiation = (client_verify, computed) } in
  ({ state with machina = Client machina ; session = session :: state.session }, [])

let answer_hello_request state =
  let session_data state = match state.session with
    | []     -> fail_handshake
    | x :: _ -> return x

  and produce_client_hello session config exts =
     let dch, _ = default_client_hello config in
     let ch = { dch with extensions = exts @ dch.extensions } in
     let raw = Writer.assemble_handshake (ClientHello ch) in
     let machina = AwaitServerHelloRenegotiate (session, ch, [raw]) in
     Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake (ClientHello ch) ;
     ({ state with machina = Client machina }, [`Record (Packet.HANDSHAKE, raw)])
  in

  if state.config.use_reneg then
    session_data state >|= fun session ->
    let ext =
      let cvd, _ = session.renegotiation in
      SecureRenegotiation cvd
    in
    produce_client_hello session state.config [ext]
  else
    let no_reneg = Writer.assemble_alert ~level:Packet.WARNING Packet.NO_RENEGOTIATION in
    return (state, [`Record (Packet.ALERT, no_reneg)])

let handle_change_cipher_spec cs state packet =
  let open Reader in
  match parse_change_cipher_spec packet, cs with
  | Or_error.Ok (), AwaitServerChangeCipherSpec (session, server_ctx, client_verify, log) ->
     assure (Cs.null state.hs_fragment) >>= fun () ->
     let machina = AwaitServerFinished (session, client_verify, log) in
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
       | AwaitServerHello (ch, log), ServerHello sh ->
          answer_server_hello hs ch sh buf log
       | AwaitServerHelloRenegotiate (session, ch, log), ServerHello sh ->
          answer_server_hello_renegotiate hs session ch sh buf log
       | AwaitCertificate_RSA (session, log), Certificate cs ->
          answer_certificate_RSA hs session cs buf log
       | AwaitCertificate_DHE_RSA (session, log), Certificate cs ->
          answer_certificate_DHE_RSA hs session cs buf log
       | AwaitServerKeyExchange_DHE_RSA (session, log), ServerKeyExchange kex ->
          answer_server_key_exchange_DHE_RSA hs session kex buf log
       | AwaitServerHelloDone (session, kex, pms, log), ServerHelloDone ->
          answer_server_hello_done hs session kex pms buf log
       | AwaitServerFinished (session, client_verify, log), Finished fin ->
          answer_server_finished hs session client_verify fin log
       | Established, HelloRequest ->
          answer_hello_request hs
       | _, _ -> fail_handshake )
  | Or_error.Error _ -> fail Packet.UNEXPECTED_MESSAGE

