open Nocrypto

open Utils

open Core
open State
open Handshake_common
open Config

let (<+>) = Cs.(<+>)

let hello_request state =
  if state.config.use_reneg then
    let hr = HelloRequest in
    Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake hr ;
    let state = { state with machina = Server AwaitClientHelloRenegotiate } in
    return (state, [`Record (Packet.HANDSHAKE, Writer.assemble_handshake hr)])
  else
    fail_handshake


let answer_client_finished state session client_fin raw log =
  let client, server =
    let checksum = Handshake_crypto.finished state.protocol_version session.master_secret in
    (checksum "client finished" log, checksum "server finished" (log @ [raw]))
  in
  assure (Cs.equal client client_fin)
  >>= fun () ->
  let fin = Finished server in
  let fin_raw = Writer.assemble_handshake fin in
  (* we really do not want to have any leftover handshake fragments *)
  assure (Cs.null state.hs_fragment)
  >|= fun () ->
  let session = { session with renegotiation = (client, server) }
  and machina = Server Established
  in
  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake fin ;
  ({ state with machina ; session = session :: state.session },
   [`Record (Packet.HANDSHAKE, fin_raw)])

let establish_master_secret state session premastersecret raw log =
  let client_ctx, server_ctx, master_secret =
    Handshake_crypto.initialise_crypto_ctx state.protocol_version session premastersecret
  in
  let session = { session with master_secret = master_secret } in
  let machina =
    AwaitClientChangeCipherSpec (session, server_ctx, client_ctx, log @ [raw])
  in
  Tracing.cs ~tag:"master-secret" master_secret ;
  ({ state with machina = Server machina }, [])

let private_key session =
  match session.own_private_key with
    | Some priv -> return priv
    | None      -> fail_handshake

let answer_client_key_exchange_RSA state session kex raw log =
  (* due to bleichenbacher attach, we should use a random pms *)
  (* then we do not leak any decryption or padding errors! *)
  let other = Writer.assemble_protocol_version state.protocol_version <+> Rng.generate 46 in
  let validate_premastersecret k =
    (* Client implementations MUST always send the correct version number in
       PreMasterSecret.  If ClientHello.client_version is TLS 1.1 or higher,
       server implementations MUST check the version number as described in
       the note below.  If the version number is TLS 1.0 or earlier, server
       implementations SHOULD check the version number, but MAY have a
       configuration option to disable the check.  Note that if the check
       fails, the PreMasterSecret SHOULD be randomized as described below *)
    (* we do not provide an option to disable the version checking (yet!) *)
    match Cstruct.len k == 48, Reader.parse_any_version k with
    | true, Reader.Or_error.Ok c_ver when c_ver = session.client_version -> k
    | _                                                                  -> other
  in

  private_key session >|= fun priv ->

  let pms = match Rsa.PKCS1.decrypt priv kex with
    | None   -> validate_premastersecret other
    | Some k -> validate_premastersecret k
  in
  establish_master_secret state session pms raw log

let answer_client_key_exchange_DHE_RSA state session (group, secret) kex raw log =
  match Crypto.dh_shared group secret kex with
  | None     -> fail Packet.INSUFFICIENT_SECURITY
  | Some pms -> return (establish_master_secret state session pms raw log)

let sig_algs client_hello =
  map_find client_hello.extensions ~f:function
           | SignatureAlgorithms xs -> Some xs
           | _                      -> None

let answer_client_hello_common state session reneg ch raw =
  let server_hello session reneg =
    let server_hello =
      (* RFC 4366: server shall reply with an empty hostname extension *)
      let host = option [] (fun _ -> [Hostname None]) session.own_name
      and random = Rng.generate 32
      and secren =
        match reneg with
        | None            -> SecureRenegotiation (Cstruct.create 0)
        | Some (cvd, svd) -> SecureRenegotiation (cvd <+> svd)
      in
      { version      = state.protocol_version ;
        random       = random ;
        sessionid    = None ;
        ciphersuites = session.ciphersuite ;
        extensions   = secren :: host }
    in
    let sh = ServerHello server_hello in
    Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake sh ;
    (Writer.assemble_handshake sh, { session with server_random = server_hello.random })

  and server_cert session config =
    let cert_needed =
      Ciphersuite.(needs_certificate @@ ciphersuite_kex session.ciphersuite) in
    ( match config.own_certificate, cert_needed with
      (* XXX: select based on session.own_name *)
      | Some (certs, pk), true  -> return (certs, Some pk)
      | _               , false -> return ([], None)
      | _               , _     -> fail_handshake
      (* ^^^ Rig ciphersuite selection never to end up with one than needs a cert
       * if we haven't got one. *)
    ) >|= fun (certs, pk) ->
    let cert = Certificate (List.map Certificate.cs_of_cert certs) in
    Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake cert ;
    ([ Writer.assemble_handshake cert ],
     { session with own_certificate = certs ; own_private_key = pk })

  and kex_dhe_rsa config session version sig_algs =
    let group         = Dh.Group.oakley_2 in (* rfc2409 1024-bit group *)
    let (secret, msg) = Dh.gen_secret group in
    let dh_state      = group, secret in
    let written =
      let dh_param = Crypto.dh_params_pack group msg in
      Writer.assemble_dh_parameters dh_param in

    let data = session.client_random <+> session.server_random <+> written in

    let signature pk =
      let sign x =
        try return (Rsa.PKCS1.sign pk x)
        with _ -> fail_handshake
      in
      match version with
      | TLS_1_0 | TLS_1_1 ->
          sign Hash.( MD5.digest data <+> SHA1.digest data )
          >|= Writer.assemble_digitally_signed
      | TLS_1_2 ->
          (* if no signature_algorithms extension is sent by the client,
             support for md5 and sha1 can be safely assumed! *)
        ( match sig_algs with
          | None              -> return `SHA1
          | Some client_algos ->
              let client_hashes =
                List.(map fst @@ filter (fun (_, x) -> x = Packet.RSA) client_algos)
              in
              match first_match client_hashes config.hashes with
              | None      -> fail_handshake
              | Some hash -> return hash )
          >>= fun hash_algo ->
            let hash = Hash.digest hash_algo data in
            let cs = Asn_grammars.pkcs1_digest_info_to_cstruct (hash_algo, hash) in
            sign cs >|= Writer.assemble_digitally_signed_1_2 hash_algo Packet.RSA
    in

    private_key session >>= signature >|= fun sgn ->
      let kex = ServerKeyExchange (written <+> sgn) in
      let hs = Writer.assemble_handshake kex in
      Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake kex ;
      (hs, dh_state) in

  let sh, session = server_hello session reneg in
  server_cert session state.config >>= fun (certificates, session) ->
  let hello_done = Writer.assemble_handshake ServerHelloDone in

  ( match Ciphersuite.ciphersuite_kex session.ciphersuite with
    | Ciphersuite.DHE_RSA ->
        kex_dhe_rsa state.config session state.protocol_version (sig_algs ch) >>= fun (kex, dh) ->
        let outs = sh :: certificates @ [ kex ; hello_done] in
        let machina = AwaitClientKeyExchange_DHE_RSA (session, dh, raw :: outs) in
        Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake ServerHelloDone ;
        return (outs, machina)
    | Ciphersuite.RSA ->
        let outs = sh :: certificates @ [ hello_done] in
        let machina = AwaitClientKeyExchange_RSA (session, raw :: outs) in
        Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake ServerHelloDone ;
        return (outs, machina)
    ) >|= fun (out_recs, machina) ->

  ({ state with machina = Server machina },
   [`Record (Packet.HANDSHAKE, Cs.appends out_recs)])

let agreed_cipher server_supported requested =
  let cciphers = filter_map ~f:Ciphersuite.any_ciphersuite_to_ciphersuite requested in
  match first_match cciphers server_supported with
  | Some x -> return x
  | None   -> fail_handshake

let agreed_version supported requested =
  match supported_protocol_version supported requested with
  | Some x -> return x
  | None   -> fail Packet.PROTOCOL_VERSION

let answer_client_hello state (ch : client_hello) raw =
  let ensure_reneg require ciphers their_data  =
    let reneg_cs = List.mem Packet.TLS_EMPTY_RENEGOTIATION_INFO_SCSV ciphers in
    match require, reneg_cs, their_data with
    | _    , _   , Some x -> assure (Cs.null x)
    | _    , true, _      -> return ()
    | false, _   , _      -> return ()
    | _    , _   , _      -> fail_handshake
  in

  let process_client_hello config ch =
    let cciphers = ch.ciphersuites in
    assure (client_hello_valid ch) >>= fun () ->
    agreed_version config.protocol_versions ch.version >>= fun version ->
    agreed_cipher config.ciphers cciphers >>= fun cipher ->
    let theirs = get_secure_renegotiation ch.extensions in
    ensure_reneg config.secure_reneg cciphers theirs >|= fun () ->

    Tracing.sexpf ~tag:"version" ~f:sexp_of_tls_version version ;
    Tracing.sexpf ~tag:"cipher" ~f:Ciphersuite.sexp_of_ciphersuite cipher ;

    ({ empty_session with
       client_random    = ch.random ;
       client_version   = ch.version ;
       ciphersuite      = cipher ;
       own_name         = hostname ch }, version)
  in

  process_client_hello state.config ch >>= fun (session, protocol_version) ->
  answer_client_hello_common { state with protocol_version } session None ch raw

let answer_client_hello_reneg state (ch : client_hello) raw =
  (* ensure reneg allowed and supplied *)
  let ensure_reneg require our_data their_data  =
    match require, our_data, their_data with
    | _    , (cvd, _), Some x -> assure (Cs.equal cvd x)
    | false, _       , _      -> return ()
    | true , _       , _      -> fail_handshake
  in

  let process_client_hello config oldsession oldversion ours ch =
    let cciphers = ch.ciphersuites in
    assure (client_hello_valid ch) >>= fun () ->
    agreed_version config.protocol_versions ch.version >>= fun version ->
    assure (version = oldversion) >>= fun () ->
    agreed_cipher config.ciphers cciphers >>= fun cipher ->
    let theirs = get_secure_renegotiation ch.extensions in
    ensure_reneg config.secure_reneg ours theirs >|= fun () ->

    Tracing.sexpf ~tag:"version" ~f:sexp_of_tls_version version ;
    Tracing.sexpf ~tag:"cipher" ~f:Ciphersuite.sexp_of_ciphersuite cipher ;

    { empty_session with
      client_random    = ch.random ;
      client_version   = ch.version ;
      ciphersuite      = cipher ;
      own_name         = hostname ch }
  in

  let config = state.config in
  match config.use_reneg, state.session with
  | true, session :: _  ->
     let reneg = session.renegotiation in
     process_client_hello config session state.protocol_version reneg ch >>= fun session ->
     answer_client_hello_common state session (Some reneg) ch raw
  | _   , _             -> fail_handshake

let handle_change_cipher_spec ss state packet =
  let open Reader in
  match parse_change_cipher_spec packet, ss with
  | Or_error.Ok (), AwaitClientChangeCipherSpec (session, server_ctx, client_ctx, log) ->
     assure (Cs.null state.hs_fragment)
     >>= fun () ->
     let ccs = change_cipher_spec in
     let machina = AwaitClientFinished (session, log)
     in
     Tracing.cs ~tag:"change-cipher-spec-in" packet ;
     Tracing.cs ~tag:"change-cipher-spec-out" packet ;

     return ({ state with machina = Server machina },
             [`Record ccs; `Change_enc (Some server_ctx)],
             `Change_dec (Some client_ctx))
  | _ ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_handshake ss hs buf =
  let open Reader in
  match parse_handshake buf with
  | Or_error.Ok handshake ->
     Tracing.sexpf ~tag:"handshake-in" ~f:sexp_of_tls_handshake handshake;
     ( match ss, handshake with
       | AwaitClientHello, ClientHello ch ->
          answer_client_hello hs ch buf
       | AwaitClientKeyExchange_RSA (session, log), ClientKeyExchange kex ->
          answer_client_key_exchange_RSA hs session kex buf log
       | AwaitClientKeyExchange_DHE_RSA (session, dh_sent, log), ClientKeyExchange kex ->
          answer_client_key_exchange_DHE_RSA hs session dh_sent kex buf log
       | AwaitClientFinished (session, log), Finished fin ->
          answer_client_finished hs session fin buf log
       | Established, ClientHello ch -> (* client-initiated renegotiation *)
          answer_client_hello_reneg hs ch buf
       | AwaitClientHelloRenegotiate, ClientHello ch -> (* hello-request send, renegotiation *)
          answer_client_hello_reneg hs ch buf
       | _, _-> fail_handshake )
  | Or_error.Error _ -> fail Packet.UNEXPECTED_MESSAGE
