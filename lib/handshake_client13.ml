open State
open Core
open Handshake_common
open Config

let answer_server_hello state ch (sh : server_hello) secrets raw log =
  (* assume SH valid, version 1.3, extensions are subset *)
  match Ciphersuite.ciphersuite_to_ciphersuite13 sh.ciphersuite with
  | None -> Error (`Fatal `InvalidServerHello)
  | Some cipher ->
    let* () = guard (List.mem cipher (ciphers13 state.config)) (`Fatal `InvalidServerHello) in
    let* () = guard (Cstruct.length state.hs_fragment = 0) (`Fatal `HandshakeFragmentsNotEmpty) in

    (* TODO: PSK *)
    (* TODO: early_secret elsewhere *)
    match Utils.map_find ~f:(function `KeyShare ks -> Some ks | _ -> None) sh.extensions with
    | None -> Error (`Fatal `InvalidServerHello)
    | Some (g, share) ->
      match List.find_opt (fun (g', _) -> g = g') secrets with
      | None -> Error (`Fatal `InvalidServerHello)
      | Some (_, secret) ->
        let* shared = Handshake_crypto13.dh_shared secret share in
        let hlen = Mirage_crypto.Hash.digest_size (Ciphersuite.hash13 cipher) in
        let* psk, resumed =
          match
            Utils.map_find ~f:(function `PreSharedKey idx -> Some idx | _ -> None) sh.extensions,
            state.config.Config.cached_ticket
          with
          | None, _ | _, None -> Ok (Cstruct.create hlen, false)
          | Some idx, Some (psk, _epoch) ->
            let* () = guard (idx = 0) (`Fatal `InvalidServerHello) in
            Ok (psk.secret, true)
        in
        let early_secret = Handshake_crypto13.(derive (empty cipher) psk) in
        let hs_secret = Handshake_crypto13.derive early_secret shared in
        let log = log <+> raw in
        let server_hs_secret, server_ctx, client_hs_secret, client_ctx =
          Handshake_crypto13.hs_ctx hs_secret log in
        let master_secret =
          Handshake_crypto13.derive hs_secret (Cstruct.create hlen)
        in
        let session =
          let base = empty_session13 cipher in
          let common_session_data13 =
            { base.common_session_data13 with
              server_random = sh.server_random ;
              client_random = ch.client_random ;
              master_secret = master_secret.secret }
          in
          { base with master_secret ; common_session_data13 ; resumed }
        in
        let st = AwaitServerEncryptedExtensions13 (session, server_hs_secret, client_hs_secret, log) in
        Ok ({ state with machina = Client13 st ; protocol_version = `TLS_1_3 },
            [ `Change_enc client_ctx ; `Change_dec server_ctx ])

(* called from handshake_client.ml *)
let answer_hello_retry_request state (ch : client_hello) hrr _secrets raw log =
  (* when is a HRR invalid / what do we need to check?
     -> we advertised the group and cipher
     -> TODO we did advertise such a keyshare already (does it matter?)
  *)
  let* () = guard (`TLS_1_3 = hrr.retry_version) (`Fatal `InvalidMessage) in
  let* () = guard (List.mem hrr.selected_group state.config.groups) (`Fatal `InvalidMessage) in
  let* () = guard (List.mem hrr.ciphersuite (ciphers13 state.config)) (`Fatal `InvalidMessage) in
  (* generate a fresh keyshare *)
  let secret, keyshare =
    let g = hrr.selected_group in
    let priv, share = Handshake_crypto13.dh_gen_key g in
    (g, priv), (group_to_named_group g, share)
  in
  (* append server extensions (i.e. cookie!) *)
  let cookie = match Utils.map_find ~f:(function `Cookie c -> Some c | _ -> None) hrr.extensions with
    | None -> []
    | Some c -> [ `Cookie c ]
  in
  (* use the same extensions as in original CH, apart from PSK!? and early_data *)
  let other_exts = List.filter (function `KeyShare _ -> false | _ -> true) ch.extensions in
  let new_ch = { ch with extensions = `KeyShare [keyshare] :: other_exts @ cookie} in
  let new_ch_raw = Writer.assemble_handshake (ClientHello new_ch) in
  let ch0_data = Mirage_crypto.Hash.digest (Ciphersuite.hash13 hrr.ciphersuite) log in
  let ch0_hdr = Writer.assemble_message_hash (Cstruct.length ch0_data) in
  let st = AwaitServerHello13 (new_ch, [secret], Cstruct.concat [ ch0_hdr ; ch0_data ; raw ; new_ch_raw ]) in

  Tracing.hs ~tag:"handshake-out" (ClientHello new_ch);
  Ok ({ state with machina = Client13 st ; protocol_version = `TLS_1_3 }, [`Record (Packet.HANDSHAKE, new_ch_raw)])

let answer_encrypted_extensions state (session : session_data13) server_hs_secret client_hs_secret ee raw log =
  (* TODO we now know: - hostname - early_data (preserve this in session!!) *)
  (* next message is either CertificateRequest or Certificate (or finished if PSK) *)
  let alpn_protocol = Utils.map_find ~f:(function `ALPN proto -> Some proto | _ -> None) ee in
  let session =
    let common_session_data13 = { session.common_session_data13 with alpn_protocol } in
    { session with common_session_data13 }
  in
  let st =
    if session.resumed then
      AwaitServerFinished13 (session, server_hs_secret, client_hs_secret, None, log <+> raw)
    else
      AwaitServerCertificateRequestOrCertificate13 (session, server_hs_secret, client_hs_secret, log <+> raw)
  in
  Ok ({ state with machina = Client13 st }, [])

let answer_certificate state (session : session_data13) server_hs_secret client_hs_secret sigalgs certs raw log =
  (* certificates are (cs, ext) list - ext being statusrequest or signed_cert_timestamp *)
  let certs = List.map fst certs in
  let* peer_certificate, received_certificates, peer_certificate_chain, trust_anchor =
    validate_chain state.config.authenticator certs state.config.ip state.config.peer_name
  in
  let session =
    let common_session_data13 = {
      session.common_session_data13 with
      received_certificates ; peer_certificate_chain ; peer_certificate ; trust_anchor
    } in
    { session with common_session_data13 }
  in
  let st = AwaitServerCertificateVerify13 (session, server_hs_secret, client_hs_secret, sigalgs, log <+> raw) in
  Ok ({ state with machina = Client13 st }, [])

let answer_certificate_verify (state : handshake_state) (session : session_data13) server_hs_secret client_hs_secret sigalgs cv raw log =
  let tbs = Mirage_crypto.Hash.digest (Ciphersuite.hash13 session.ciphersuite13) log in
  let* () =
    verify_digitally_signed state.protocol_version
      ~context_string:"TLS 1.3, server CertificateVerify"
      state.config.signature_algorithms cv tbs
      session.common_session_data13.peer_certificate
  in
  let st = AwaitServerFinished13 (session, server_hs_secret, client_hs_secret, sigalgs, log <+> raw) in
  Ok ({ state with machina = Client13 st }, [])

let answer_certificate_request (state : handshake_state) (session : session_data13) server_hs_secret client_hs_secret extensions raw log =
  (* TODO respect extensions (CA, OIDfilter)! *)
  let session =
    let common_session_data13 = { session.common_session_data13 with client_auth = true } in
    { session with common_session_data13 }
  in
  let sigalgs = Utils.map_find ~f:(function `SignatureAlgorithms s -> Some s | _ -> None) extensions in
  let st = AwaitServerCertificate13 (session, server_hs_secret, client_hs_secret, sigalgs, log <+> raw) in
  Ok ({ state with machina = Client13 st }, [])

let answer_finished state (session : session_data13) server_hs_secret client_hs_secret sigalgs fin raw log =
  let hash = Ciphersuite.hash13 session.ciphersuite13 in
  let f_data = Handshake_crypto13.finished hash server_hs_secret log in
  let* () = guard (Cstruct.equal fin f_data) (`Fatal `BadFinished) in
  let* () = guard (Cstruct.length state.hs_fragment = 0) (`Fatal `HandshakeFragmentsNotEmpty) in
  let log = log <+> raw in
  let server_app_secret, server_app_ctx, client_app_secret, client_app_ctx =
    Handshake_crypto13.app_ctx session.master_secret log
  in

  let* c_cv, log =
    if session.common_session_data13.client_auth then
      let own_certificate, own_private_key =
        match state.config.Config.own_certificates with
        | `Single (chain, priv) -> (chain, Some priv)
        | _ -> ([], None)
      in
      let certificate =
        let cs = List.map X509.Certificate.encode_der own_certificate in
        Certificate (Writer.assemble_certificates_1_3 Cstruct.empty cs)
      in
      let cert_raw = Writer.assemble_handshake certificate in
      Tracing.hs ~tag:"handshake-out" certificate ;
      let log = log <+> cert_raw in
      match own_private_key with
      | None ->
        Ok ([cert_raw], log)
      | Some priv ->
        let tbs = Mirage_crypto.Hash.digest hash log in
        let* signed =
          signature `TLS_1_3 ~context_string:"TLS 1.3, client CertificateVerify"
            tbs sigalgs state.config.Config.signature_algorithms priv
        in
        let cv = CertificateVerify signed in
        Tracing.hs ~tag:"handshake-out" cv ;
        let cv_raw = Writer.assemble_handshake cv in
        Ok ([ cert_raw ; cv_raw ], log <+> cv_raw)
    else
      Ok ([], log)
  in

  let myfin = Handshake_crypto13.finished hash client_hs_secret log in
  let mfin = Writer.assemble_handshake (Finished myfin) in

  let resumption_secret = Handshake_crypto13.resumption session.master_secret  (log <+> mfin) in
  let session = { session with resumption_secret ; client_app_secret ; server_app_secret } in
  let machina = Client13 Established13 in

  Tracing.hs ~tag:"handshake-out" (Finished myfin);

  Ok ({ state with machina ; session = `TLS13 session :: state.session },
      List.map (fun data -> `Record (Packet.HANDSHAKE, data)) c_cv @
      [ `Record (Packet.HANDSHAKE, mfin) ;
        `Change_dec server_app_ctx ; `Change_enc client_app_ctx ])

let answer_session_ticket state st =
  (match state.config.ticket_cache with
   | None -> ()
   | Some cache ->
     (* looks like we'll need the resumption secret in the state (we can compute once finished is done)! *)
     match state.session with
     | `TLS13 session :: _ ->
       let epoch = epoch_of_session false state.config.Config.peer_name `TLS_1_3 (`TLS13 session) in
       let secret = Handshake_crypto13.res_secret
           (Ciphersuite.hash13 session.ciphersuite13)
           session.resumption_secret st.nonce
       in
       let issued_at = cache.timestamp () in
       let early_data = match Utils.map_find ~f:(function `EarlyDataIndication x -> Some x | _ -> None) st.extensions with
         | None -> 0l
         | Some x -> x
       in
       let psk = { identifier = st.ticket ; obfuscation = st.age_add ; secret ; lifetime = st.lifetime ; early_data ; issued_at } in
       cache.ticket_granted psk epoch
     | _ -> ());
  Ok (state, [])

let handle_key_update state req =
  match state.session with
  | `TLS13 session :: _ ->
    let* () = guard (Cstruct.length state.hs_fragment = 0) (`Fatal `HandshakeFragmentsNotEmpty) in
    let server_app_secret, server_ctx =
      Handshake_crypto13.app_secret_n_1 session.master_secret session.server_app_secret
    in
    let session' = { session with server_app_secret } in
    let session', out = match req with
      | Packet.UPDATE_NOT_REQUESTED -> session', []
      | Packet.UPDATE_REQUESTED ->
        let client_app_secret, client_ctx =
          Handshake_crypto13.app_secret_n_1 session.master_secret session.client_app_secret
        in
        let ku = KeyUpdate Packet.UPDATE_NOT_REQUESTED in
        Tracing.hs ~tag:"handshake-out" ku ;
        let ku_raw = Writer.assemble_handshake ku in
        { session' with client_app_secret },
        [ `Record (Packet.HANDSHAKE, ku_raw); `Change_enc client_ctx ]
    in
    let session = `TLS13 session' :: state.session in
    let state' = { state with machina = Server13 Established13 ; session } in
    Ok (state', `Change_dec server_ctx :: out)
  | _ -> Error (`Fatal `InvalidSession)

let handle_handshake cs hs buf =
  let open Reader in
  let* handshake = map_reader_error (parse_handshake buf) in
  Tracing.hs ~tag:"handshake-in" handshake;
  match cs, handshake with
  | AwaitServerHello13 (ch, secrets, log), ServerHello sh ->
    answer_server_hello hs ch sh secrets buf log
  | AwaitServerEncryptedExtensions13 (sd, es, ss, log), EncryptedExtensions ee ->
    answer_encrypted_extensions hs sd es ss ee buf log
  | AwaitServerCertificateRequestOrCertificate13 (sd, es, ss, log), CertificateRequest cr ->
    let* ctx, exts = map_reader_error (parse_certificate_request_1_3 cr) in
    (* during handshake, context must be empty! *)
    let* () = guard (ctx = None) (`Fatal `InvalidMessage) in
    answer_certificate_request hs sd es ss exts buf log
  | AwaitServerCertificateRequestOrCertificate13 (sd, es, ss, log), Certificate cs ->
    let* con, cs = map_reader_error (parse_certificates_1_3 cs) in
    (* during handshake, context must be empty! and we'll not get any new certificate from server *)
    let* () = guard (Cstruct.length con = 0) (`Fatal `InvalidMessage) in
    answer_certificate hs sd es ss None cs buf log
  | AwaitServerCertificate13 (sd, es, ss, sigalgs, log), Certificate cs ->
    let* con, cs = map_reader_error (parse_certificates_1_3 cs) in
    (* during handshake, context must be empty! and we'll not get any new certificate from server *)
    let* () = guard (Cstruct.length con = 0) (`Fatal `InvalidMessage) in
    answer_certificate hs sd es ss sigalgs cs buf log
  | AwaitServerCertificateVerify13 (sd, es, ss, sigalgs, log), CertificateVerify cv ->
    answer_certificate_verify hs sd es ss sigalgs cv buf log
  | AwaitServerFinished13 (sd, es, ss, sigalgs, log), Finished fin ->
    answer_finished hs sd es ss sigalgs fin buf log
  | Established13, SessionTicket se -> answer_session_ticket hs se
  | Established13, CertificateRequest _ ->
    Error (`Fatal (`UnexpectedHandshake handshake)) (* TODO send out C, CV, F *)
  | Established13, KeyUpdate req -> handle_key_update hs req
  | _, hs -> Error (`Fatal (`UnexpectedHandshake hs))
