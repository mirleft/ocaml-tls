open Core
open Nocrypto
open Handshake_common_utils
open Handshake_common_utils.Or_alert
open Config

let (<+>) = Utils.Cs.(<+>)

let default_client_hello config =
  let host = match config.peer_name with
    | None   -> []
    | Some x -> [Hostname (Some x)]
  in
  let version = max_protocol_version config in
  let signature_algos = match version with
    | TLS_1_0 | TLS_1_1 -> []
    | TLS_1_2 ->
       let supported = List.map (fun h -> (h, Packet.RSA)) config.hashes in
       [SignatureAlgorithms supported]
  in
  let ch = {
    version      = max_protocol_version config ;
    random       = Rng.generate 32 ;
    sessionid    = None ;
    ciphersuites = config.ciphers ;
    extensions   = host @ signature_algos
  }
  in
  ( ch , { server_random = Cstruct.create 0 ;
           client_random = ch.random ;
           client_version = ch.version ;
           cipher = List.hd ch.ciphersuites })

let answer_server_hello state params (sh : server_hello) raw log =
  let find_version requested config server_version =
    match
      requested >= server_version,
      supported_protocol_version config server_version
    with
    | true, Some _ -> return ()
    | _ -> fail Packet.PROTOCOL_VERSION

  and validate_cipher suites suite =
    match List.mem suite suites with
    | true -> return ()
    | false -> fail Packet.HANDSHAKE_FAILURE

  and validate_rekeying rekeying extensions =
    match rekeying with
    | None            -> check_reneg (Cstruct.create 0) extensions
    | Some (cvd, svd) -> check_reneg (cvd <+> svd) extensions

  and adjust_params params sh =
    { params with
        server_random = sh.random ;
        cipher = sh.ciphersuites }
  in

  find_version params.client_version state.config sh.version >>= fun () ->
  validate_cipher state.config.ciphers sh.ciphersuites >>= fun () ->
  validate_rekeying state.rekeying sh.extensions >>= fun () ->

  let machina = ServerHelloReceived (adjust_params params sh, log @ [raw]) in
  let state = { state with version = sh.version ; machina = Client machina } in
  return (state, [], `Pass)

let answer_certificate state params cs raw log =
  let open Certificate in

  let parse css =
    match parse_stack css with
    | None       -> fail Packet.BAD_CERTIFICATE
    | Some stack -> return stack

  (* actually, depending on key exchange method we should check for validity of cert:
      Key Exchange Alg.  Certificate Key Type

      RSA                RSA public key; the certificate MUST allow the
      RSA_PSK            key to be used for encryption (the
                         keyEncipherment bit MUST be set if the key
                         usage extension is present).
                         Note: RSA_PSK is defined in [TLSPSK].

      DHE_RSA            RSA public key; the certificate MUST allow the
      ECDHE_RSA          key to be used for signing (the
                         digitalSignature bit MUST be set if the key
                         usage extension is present) with the signature
                         scheme and hash algorithm that will be employed
                         in the server key exchange message.
                         Note: ECDHE_RSA is defined in [TLSECC].

      DHE_DSS            DSA public key; the certificate MUST allow the
                         key to be used for signing with the hash
                         algorithm that will be employed in the server
                         key exchange message.

      DH_DSS             Diffie-Hellman public key; the keyAgreement bit
      DH_RSA             MUST be set if the key usage extension is
                         present.

      ECDH_ECDSA         ECDH-capable public key; the public key MUST
      ECDH_RSA           use a curve and point format supported by the
                         client, as described in [TLSECC].

      ECDHE_ECDSA        ECDSA-capable public key; the certificate MUST
                         allow the key to be used for signing with the
                         hash algorithm that will be employed in the
                         server key exchange message.  The public key
                         MUST use a curve and point format supported by
                         the client, as described in  [TLSECC].
   *)
  and validate validator server_name ((server, _) as stack) =
    match
      X509.Validator.validate validator ?host:server_name stack
    with
    | `Fail SelfSigned         -> fail Packet.UNKNOWN_CA
    | `Fail NoTrustAnchor      -> fail Packet.UNKNOWN_CA
    | `Fail CertificateExpired -> fail Packet.CERTIFICATE_EXPIRED
    | `Fail _                  -> fail Packet.BAD_CERTIFICATE
    | `Ok                      -> return server
  in

  ( match state.config.validator with
    | None -> parse cs >>= fun (server, _) ->
              return server
    | Some validator -> parse cs >>= validate validator state.config.peer_name ) >>= fun peer_cert ->

  let machina =
    let data = log @ [raw] in
    Ciphersuite.(match ciphersuite_kex params.cipher with
                 | RSA     -> ServerCertificateReceived_RSA (params, peer_cert, data)
                 | DHE_RSA -> ServerCertificateReceived_DHE_RSA (params, peer_cert, data))
  in
  return ({ state with machina = Client machina }, [], `Pass)

let peer_rsa_key cert =
  let open Asn_grammars in
  ( match Certificate.(asn_of_cert cert).tbs_cert.pk_info with
    | PK.RSA key -> return key
    | _          -> fail Packet.HANDSHAKE_FAILURE )

let answer_server_key_exchange_DHE_RSA state params cert kex raw log =
  let extract_dh_params kex =
    Reader.(match parse_dh_parameters kex with
            | Or_error.Ok data -> return data
            | Or_error.Error _ -> fail Packet.HANDSHAKE_FAILURE)

  and signature_verifier version data =
    match version with
    | TLS_1_0 | TLS_1_1 ->
        Reader.( match parse_digitally_signed data with
                 | Or_error.Ok signature ->
                    let compare_hashes should data =
                      let computed_sig = Hash.(MD5.digest data <+> SHA1.digest data) in
                      fail_neq should computed_sig Packet.HANDSHAKE_FAILURE
                    in
                    return (signature, compare_hashes)
                 | Or_error.Error _      -> fail Packet.HANDSHAKE_FAILURE )
    | TLS_1_2 ->
       Reader.( match parse_digitally_signed_1_2 data with
                | Or_error.Ok (hash_algo, Packet.RSA, signature) ->
                   let compare_hashes should data =
                     match Crypto.pkcs1_digest_info_of_cstruct should with
                     | Some (hash_algo', target) when hash_algo = hash_algo' ->
                        ( match Crypto.hash_eq hash_algo ~target data with
                          | true -> return ()
                          | false -> fail Packet.HANDSHAKE_FAILURE )
                     | _ -> fail Packet.HANDSHAKE_FAILURE
                   in
                   return (signature, compare_hashes)
                | Or_error.Error _ -> fail Packet.HANDSHAKE_FAILURE )

  and extract_signature pubkey raw_signature =
    match Crypto.verifyRSA_and_unpadPKCS1 pubkey raw_signature with
    | Some signature -> return signature
    | None -> fail Packet.HANDSHAKE_FAILURE

  in

  extract_dh_params kex >>= fun (dh_params, raw_dh_params, leftover) ->
  signature_verifier state.version leftover >>= fun (raw_signature, verifier) ->
  peer_rsa_key cert >>= fun pubkey ->
  extract_signature pubkey raw_signature >>= fun signature ->
  let sigdata = params.client_random <+> params.server_random <+> raw_dh_params in
  verifier signature sigdata >>= fun () ->
  let dh_received = Crypto.dh_params_unpack dh_params in
  let machina = ServerKeyExchangeReceived_DHE_RSA (params, dh_received, log @ [raw]) in
  return ({ state with machina = Client machina }, [], `Pass)

let answer_server_hello_done_common state kex premaster params raw log =
  let ckex = Writer.assemble_handshake (ClientKeyExchange kex) in
  let ccs = change_cipher_spec in
  let client_ctx, server_ctx, master_secret = initialise_crypto_ctx state.version params premaster in
  let to_fin = log @ [raw; ckex] in
  let checksum = Crypto.finished state.version master_secret "client finished" to_fin in
  let fin = Writer.assemble_handshake (Finished checksum) in
  let ps = to_fin @ [fin] in
  let machina = ClientFinishedSent (server_ctx, checksum, master_secret, ps) in
  ({ state with machina = Client machina },
   [`Record (Packet.HANDSHAKE, ckex);
    `Record ccs;
    `Change_enc (Some client_ctx);
    `Record (Packet.HANDSHAKE, fin)],
   `Pass)

let answer_server_hello_done_RSA state params cert raw log =
  let ver = Writer.assemble_protocol_version params.client_version in
  let premaster = ver <+> Rng.generate 46 in
  peer_rsa_key cert >>= fun pubkey ->
  let kex = Crypto.padPKCS1_and_encryptRSA pubkey premaster in
  return (answer_server_hello_done_common state kex premaster params raw log)

let answer_server_hello_done_DHE_RSA state params (group, s_secret) raw log =
  let secret, kex = DH.gen_secret group in
  let premaster = DH.shared group secret s_secret in
  return (answer_server_hello_done_common state kex premaster params raw log)

let answer_server_finished state client_verify master_secret fin log =
  let computed = Crypto.finished state.version master_secret "server finished" log in
  fail_neq computed fin Packet.HANDSHAKE_FAILURE >>= fun () ->
  let machina = ClientEstablished in
  let rekeying = Some (client_verify, computed) in
  return ({ state with machina = Client machina ; rekeying = rekeying }, [], `Pass)

let answer_hello_request state =
  match state.config.use_rekeying with
  | false -> fail Packet.HANDSHAKE_FAILURE
  | true  ->
     (match state.rekeying with
      | None          -> fail Packet.HANDSHAKE_FAILURE
      | Some (cvd, _) -> return (SecureRenegotiation cvd) ) >>= fun (rekeying) ->

     let dch, params = default_client_hello state.config in
     let ch = { dch with
                  extensions = rekeying :: dch.extensions } in
     let raw = Writer.assemble_handshake (ClientHello ch) in
     let machina = ClientHelloSent (params, [raw]) in
     return ({ state with machina = Client machina }, [`Record (Packet.HANDSHAKE, raw)], `Pass)

let handle_change_cipher_spec cs state packet =
  (* TODO: validate packet is good (ie parse it?) *)
  match cs with
  | ClientFinishedSent (server_ctx, client_verify, ms, log) ->
     let machina = ServerChangeCipherSpecReceived (client_verify, ms, log) in
     return ({ state with machina = Client machina }, [], `Change_dec (Some server_ctx))
  | _ ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_handshake : client_handshake_state -> tls_internal_state -> Cstruct.t ->
                       ( tls_internal_state * rec_resp list * dec_resp ) or_error =
fun cs hs buf ->
  let open Reader in
  match parse_handshake buf with
  | Or_error.Ok handshake ->
     Printf.printf "HANDSHAKE: %s" (Printer.handshake_to_string handshake);
     Cstruct.hexdump buf;
     ( match cs, handshake with
       | ClientHelloSent (params, log), ServerHello sh ->
          answer_server_hello hs params sh buf log
       | ServerHelloReceived (params, log), Certificate cs ->
          answer_certificate hs params cs buf log
       | ServerCertificateReceived_RSA (params, cert, log), ServerHelloDone ->
          answer_server_hello_done_RSA hs params cert buf log
       | ServerCertificateReceived_DHE_RSA (params, cert, log), ServerKeyExchange kex ->
          answer_server_key_exchange_DHE_RSA hs params cert kex buf log
       | ServerKeyExchangeReceived_DHE_RSA (params, dh, log), ServerHelloDone ->
          answer_server_hello_done_DHE_RSA hs params dh buf log
       | ServerChangeCipherSpecReceived (client_verify, master, log), Finished fin ->
          answer_server_finished hs client_verify master fin log
       | ClientEstablished, HelloRequest ->
          answer_hello_request hs
       | _, _ -> fail Packet.HANDSHAKE_FAILURE )
  | Or_error.Error _ -> fail Packet.UNEXPECTED_MESSAGE

