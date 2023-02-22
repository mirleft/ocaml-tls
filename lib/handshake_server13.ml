open State
open Core
open Handshake_common

open Handshake_crypto13

let answer_client_hello ~hrr state ch raw =
  let* () =
    Result.map_error
      (fun e -> `Fatal (`InvalidClientHello e))
      (client_hello_valid `TLS_1_3 ch)
  in
  let* () =
    guard (not (hrr && List.mem `EarlyDataIndication ch.extensions))
      (`Fatal (`InvalidClientHello `Has0rttAfterHRR))
  in
  Tracing.debug (fun m -> m "version %a" pp_tls_version `TLS_1_3) ;

  let ciphers =
    List.filter_map Ciphersuite.any_ciphersuite_to_ciphersuite13 ch.ciphersuites
  in

  let* groups =
    let* gs =
      Option.to_result
        ~none:(`Fatal (`InvalidClientHello `NoSupportedGroupExtension))
        (Utils.map_find ~f:(function `SupportedGroups gs -> Some gs | _ -> None) ch.extensions)
    in
    Ok (List.filter_map Core.named_group_to_group gs)
  in

  let* keyshares =
    let* ks =
      Option.to_result
        ~none:(`Fatal (`InvalidClientHello `NoKeyShareExtension))
        (Utils.map_find ~f:(function `KeyShare ks -> Some ks | _ -> None) ch.extensions)
    in
    List.fold_left (fun acc (g, ks) ->
        let* acc = acc in
        match Core.named_group_to_group g with
        | None -> Ok acc
        | Some g -> Ok ((g, ks) :: acc))
      (Ok []) ks
  in

  let base_server_hello ?epoch cipher extensions =
    let ciphersuite = (cipher :> Ciphersuite.ciphersuite) in
    let sh =
      { server_version = `TLS_1_3 ;
        server_random = Mirage_crypto_rng.generate 32 ;
        sessionid = ch.sessionid ;
        ciphersuite ;
        extensions }
    in
    let session : session_data13 =
      let base = match epoch with None -> empty_session13 cipher | Some e -> session13_of_epoch cipher e in
      let common_session_data13 = {
        base.common_session_data13 with
        server_random = sh.server_random ;
        client_random = ch.client_random ;
      } in
      let resumed = match epoch with None -> false | Some _ -> true in
      { base with common_session_data13 ; ciphersuite13 = cipher ; resumed }
    in
    (sh, session)
  and keyshare group =
    try Some (snd (List.find (fun (g, _) -> g = group) keyshares)) with Not_found -> None
  in
  let keyshare_groups = List.map fst keyshares in
  let config = state.config in
  match
    Utils.first_match keyshare_groups config.Config.groups,
    Utils.first_match ciphers (Config.ciphers13 config)
  with
  | _, None -> Error (`Error (`NoConfiguredCiphersuite ciphers))
  | None, Some cipher ->
    if hrr then
      (* avoid loops CH -> HRR -> CH -> HRR -> ... *)
      Error (`Fatal `NoSupportedGroup)
    else
      (* no keyshare, looks whether there's a supported group ++ send back HRR *)
      begin match Utils.first_match groups config.Config.groups with
        | None -> Error (`Fatal `NoSupportedGroup)
        | Some group ->
          let cookie = Mirage_crypto.Hash.digest (Ciphersuite.hash13 cipher) raw in
          let hrr = { retry_version = `TLS_1_3 ; ciphersuite = cipher ; sessionid = ch.sessionid ; selected_group = group ; extensions = [ `Cookie cookie ] } in
          let hrr_raw = Writer.assemble_handshake (HelloRetryRequest hrr) in
          Tracing.hs ~tag:"handshake-out" (HelloRetryRequest hrr) ;
          (* there is no early data anymore if HRR was sent (see 4.1.2) *)
          (* but the client wouldn't know until it received the HRR *)
          let early_data_left = if List.mem `EarlyDataIndication ch.extensions then config.Config.zero_rtt else 0l in
          let machina = Server13 AwaitClientHelloHRR13 in
          Ok ({ state with early_data_left ; machina },
                  `Record (Packet.HANDSHAKE, hrr_raw) ::
                  (match ch.sessionid with
                   | None -> []
                   | Some _ -> [`Record change_cipher_spec]))
      end
  | Some group, Some cipher ->
    Log.debug (fun m -> m "cipher %a" Ciphersuite.pp_ciphersuite cipher) ;
    Log.debug (fun m -> m "group %a" pp_group group) ;

    match List.mem group groups, keyshare group with
    | false, _ | _, None -> Error (`Fatal `NoSupportedGroup) (* TODO: better error type? *)
    | _, Some keyshare ->
      (* DHE - full handshake *)

      let* log =
        if hrr then
          let* c =
            Option.to_result
              ~none:(`Fatal (`InvalidClientHello `NoCookie))
              (Utils.map_find ~f:(function `Cookie c -> Some c | _ -> None) ch.extensions)
          in
          (* log is: 254 00 00 length c :: HRR *)
          let hash_hdr = Writer.assemble_message_hash (Cstruct.length c) in
          let hrr = { retry_version = `TLS_1_3 ; ciphersuite = cipher ; sessionid = ch.sessionid ; selected_group = group ; extensions = [ `Cookie c ]} in
          let hs_buf = Writer.assemble_handshake (HelloRetryRequest hrr) in
          Ok (Cstruct.concat [ hash_hdr ; c ; hs_buf ])
        else
          Ok Cstruct.empty
      in

      let hostname = hostname ch in
      let hlen = Mirage_crypto.Hash.digest_size (Ciphersuite.hash13 cipher) in

      let early_secret, epoch, exts, can_use_early_data =
        let secret ?(psk = Cstruct.create hlen) () = Handshake_crypto13.(derive (empty cipher) psk) in
        let no_resume = secret (), None, [], false in
        match
          config.Config.ticket_cache,
          Utils.map_find ~f:(function `PreSharedKeys ids -> Some ids | _ -> None) ch.extensions,
          Utils.map_find ~f:(function `PskKeyExchangeModes ms -> Some ms | _ -> None) ch.extensions
        with
        | None, _, _ | _, None, _ -> no_resume
        | Some _, Some _, None -> no_resume (* should this lead to an error instead? *)
        | Some cache, Some ids, Some ms ->
          if not (List.mem Packet.PSK_KE_DHE ms) then
            no_resume
          else
            let idx_ids = List.mapi (fun i id -> (i, id)) ids in
            match
              List.filter (fun (_, ((id, _), _)) ->
                  match cache.Config.lookup id with None -> false | Some _ -> true)
                idx_ids
            with
            | [] ->
              Log.info (fun m -> m "found no id in psk cache") ;
              no_resume
            | (idx, ((id, obf_age), binder))::_ ->
              (* need to verify binder, do the obf_age computations + checking,
                 figure out whether the id is in our psk cache, and use the resumption secret as input
                 and Ok the idx *)
              let psk, old_epoch =
                match cache.Config.lookup id with
                | None -> assert false (* see above *)
                | Some x -> x
              in
              match Ciphersuite.(any_ciphersuite_to_ciphersuite13 (ciphersuite_to_any_ciphersuite old_epoch.ciphersuite)) with
              | None -> no_resume
              | Some c' ->
                if c' = cipher &&
                   match hostname, old_epoch.own_name with
                   | None, None -> true
                   | Some x, Some y -> Domain_name.equal x y
                   | _ -> false
                then
                  let now = cache.Config.timestamp () in
                  let server_delta_t = Ptime.diff now psk.issued_at in
                  let client_delta_t =
                    match Ptime.Span.of_float_s Int32.(to_float (sub obf_age psk.obfuscation) /. 1000.) with
                    | None ->
                      Logs.debug (fun m -> m "client_delta is not computable, using 0") ;
                      Ptime.Span.zero
                    | Some x -> x
                  in
                  (* ensure server&client_delta_t are not too far off! *)
                  match Ptime.Span.(to_int_s (abs (sub server_delta_t client_delta_t))) with
                  | None ->
                    Logs.debug (fun m -> m "s_c_delta computation lead nowhere") ;
                    no_resume
                  | Some s_c_delta ->
                    if s_c_delta > 10 then begin
                      Logs.debug (fun m -> m "delta between client and server is %d seconds, ignoring this ticket!" s_c_delta);
                      no_resume
                    end else
                      (* if ticket_creation ts + lifetime > now, continue *)
                      let until = match Ptime.add_span psk.issued_at (Ptime.Span.of_int_s (Int32.to_int cache.Config.lifetime)) with
                        | None -> Ptime.epoch
                        | Some ts -> ts
                      in
                      if Ptime.is_earlier now ~than:until then
                        let early_secret = secret ~psk:psk.secret () in
                        let binder_key = Handshake_crypto13.derive_secret early_secret "res binder" Cstruct.empty in
                        let binders_len = binders_len ids in
                        let ch_part = Cstruct.(sub raw 0 (length raw - binders_len)) in
                        let log = Cstruct.append log ch_part in
                        let binder' = Handshake_crypto13.finished early_secret.hash binder_key log in
                        if Cstruct.equal binder binder' then begin
                          (* from 4.1.2 - earlydata is not allowed after hrr *)
                          let zero = idx = 0 && not hrr && List.mem `EarlyDataIndication ch.extensions in
                          early_secret, Some old_epoch, [ `PreSharedKey idx ], zero
                        end else
                          no_resume
                      else
                        no_resume
                else
                  no_resume
      in

      let _, early_traffic_ctx = Handshake_crypto13.early_traffic early_secret raw in

      let secret, public = Handshake_crypto13.dh_gen_key group in
      let* es = Handshake_crypto13.dh_shared secret keyshare in
      let hs_secret = Handshake_crypto13.derive early_secret es in
      Tracing.cs ~tag:"hs secret" hs_secret.secret ;

      let sh, session = base_server_hello ?epoch cipher (`KeyShare (group, public) :: exts) in
      let sh_raw = Writer.assemble_handshake (ServerHello sh) in
      Tracing.hs ~tag:"handshake-out" (ServerHello sh) ;

      let log = log <+> raw <+> sh_raw in
      let server_hs_secret, server_ctx, client_hs_secret, client_ctx = hs_ctx hs_secret log in

      let* sigalgs =
        Option.to_result
          ~none:(`Fatal (`InvalidClientHello `NoSignatureAlgorithmsExtension))
          (Utils.map_find ~f:(function `SignatureAlgorithms sa -> Some sa | _ -> None) ch.extensions)
      in
      (* TODO respect certificate_signature_algs if present *)

      let f = supports_key_usage ~not_present:true `Digital_signature in
      let* chain, priv =
        let* r = agreed_cert ~f ~signature_algorithms:sigalgs config.Config.own_certificates hostname in
        match r with
        | c::cs, priv -> Ok (c::cs, priv)
        | _ -> Error (`Fatal `InvalidSession)
      in
      let* alpn_protocol = alpn_protocol config ch in
      let session =
        let common_session_data13 = { session.common_session_data13 with
                                      own_name = hostname ; own_certificate = chain ;
                                      own_private_key = Some priv ; alpn_protocol }
        in
        { session with common_session_data13 }
      in

      let ee =
        let hostname_ext = Option.fold ~none:[] ~some:(fun _ -> [`Hostname]) hostname
        and alpn = Option.fold ~none:[] ~some:(fun proto -> [`ALPN proto]) alpn_protocol
        and early_data = if can_use_early_data && config.Config.zero_rtt <> 0l then [ `EarlyDataIndication ] else []
        in
        EncryptedExtensions (hostname_ext @ alpn @ early_data)
      in
      (* TODO also max_fragment_length ; client_certificate_url ; trusted_ca_keys ; user_mapping ; client_authz ; server_authz ; cert_type ; use_srtp ; heartbeat ; alpn ; status_request_v2 ; signed_cert_timestamp ; client_cert_type ; server_cert_type *)
      let ee_raw = Writer.assemble_handshake ee in
      Tracing.hs ~tag:"handshake-out" ee ;
      let log = Cstruct.append log ee_raw in

      let* c_out, log, session' =
        if session.resumed then
          Ok ([], log, session)
        else
          let out, log, session = match config.Config.authenticator with
            | None -> [], log, session
            | Some _ ->
              let certreq =
                let exts =
                  `SignatureAlgorithms config.Config.signature_algorithms ::
                  (match config.Config.acceptable_cas with
                   | [] -> []
                   | cas -> [ `CertificateAuthorities cas ])
                in
                CertificateRequest (Writer.assemble_certificate_request_1_3 exts)
              in
              Tracing.hs ~tag:"handshake-out" certreq ;
              let raw_cert_req = Writer.assemble_handshake certreq in
              let common_session_data13 = { session.common_session_data13 with client_auth = true } in
              [raw_cert_req], log <+> raw_cert_req, { session with common_session_data13 }
          in

          let certs = List.map X509.Certificate.encode_der chain in
          let cert = Certificate (Writer.assemble_certificates_1_3 Cstruct.empty certs) in
          let cert_raw = Writer.assemble_handshake cert in
          Tracing.hs ~tag:"handshake-out" cert ;
          let log = log <+> cert_raw in

          let tbs = Mirage_crypto.Hash.digest (Ciphersuite.hash13 cipher) log in
          let* signed =
            signature `TLS_1_3
              ~context_string:"TLS 1.3, server CertificateVerify"
              tbs (Some sigalgs) config.Config.signature_algorithms priv
          in
          let cv = CertificateVerify signed in
          let cv_raw = Writer.assemble_handshake cv in
          Tracing.hs ~tag:"handshake-out" cv ;
          let log = log <+> cv_raw in
          Ok (out @ [cert_raw; cv_raw], log, session)
      in

      let master_secret = Handshake_crypto13.derive hs_secret (Cstruct.create hlen) in
      Tracing.cs ~tag:"master-secret" master_secret.secret ;

      let f_data = finished hs_secret.hash server_hs_secret log in
      let fin = Finished f_data in
      let fin_raw = Writer.assemble_handshake fin in

      Tracing.hs ~tag:"handshake-out" fin ;

      let log = log <+> fin_raw in
      let server_app_secret, server_app_ctx, client_app_secret, client_app_ctx =
        app_ctx master_secret log
      in
      let session' = { session' with server_app_secret ; client_app_secret } in

      let* () =
        guard (Cstruct.length state.hs_fragment = 0)
          (`Fatal `HandshakeFragmentsNotEmpty)
      in

      (* send sessionticket early *)
      (* TODO track the nonce across handshakes / newsessionticket messages (i.e. after post-handshake auth) - needs to be unique! *)
      let st, st_raw =
        match session.resumed, config.Config.ticket_cache with
        | true, _ | _, None -> None, []
        | false, Some cache ->
          let age_add =
            let cs = Mirage_crypto_rng.generate 4 in
            Cstruct.BE.get_uint32 cs 0
          in
          let psk_id = Mirage_crypto_rng.generate 32 in
          let nonce = Mirage_crypto_rng.generate 4 in
          let extensions = match config.Config.zero_rtt with
            | 0l -> []
            | x -> [ `EarlyDataIndication x ]
          in
          let st = { lifetime = cache.Config.lifetime ; age_add ; nonce ; ticket = psk_id ; extensions } in
          Tracing.hs ~tag:"handshake-out" (SessionTicket st) ;
          let st_raw = Writer.assemble_handshake (SessionTicket st) in
          (Some st, [st_raw])
      in

      let session =
        let common_session_data13 = { session'.common_session_data13 with master_secret = master_secret.secret } in
        { session' with common_session_data13 ; master_secret (* TODO ; exporter_secret *) }
      in
      let st, session =
        if can_use_early_data then
          (AwaitEndOfEarlyData13 (client_hs_secret, client_ctx, client_app_ctx, st, log),
           `TLS13 { session with state = `ZeroRTT } :: state.session)
        else if session.common_session_data13.client_auth then
          (AwaitClientCertificate13 (session, client_hs_secret, client_app_ctx, st, log),
           state.session)
        else
          (AwaitClientFinished13 (client_hs_secret, client_app_ctx, st, log),
           `TLS13 session :: state.session)
      in
      let early_data_left = if List.mem `EarlyDataIndication ch.extensions then config.Config.zero_rtt else 0l in
      Ok ({ state with machina = Server13 st ; session ; early_data_left },
          `Record (Packet.HANDSHAKE, sh_raw) ::
          (match ch.sessionid with
           | Some _ when not hrr -> [`Record change_cipher_spec]
           | _ -> []) @
          [ `Change_enc server_ctx ;
            `Change_dec (if can_use_early_data then early_traffic_ctx else client_ctx) ;
            `Record (Packet.HANDSHAKE, ee_raw) ] @
          List.map (fun data -> `Record (Packet.HANDSHAKE, data)) c_out @
          [ `Record (Packet.HANDSHAKE, fin_raw) ;
            `Change_enc server_app_ctx ] @
          List.map (fun data -> `Record (Packet.HANDSHAKE, data)) st_raw)

let answer_client_certificate state cert (sd : session_data13) client_fini dec_ctx st raw log =
  let* c = map_reader_error (Reader.parse_certificates_1_3 cert) in
  match c, state.config.Config.authenticator with
  | (_, []), None -> Error (`Fatal `InvalidSession) (* TODO this cannot happen *)
  | (_ctx, []), Some auth ->
    begin match auth ~host:None [] with
      | Ok anchor ->
        let trust_anchor = match anchor with
          | None -> None
          | Some (_chain, ta) -> Some ta
        in
        let common_session_data13 = { sd.common_session_data13 with trust_anchor } in
        let sd = { sd with common_session_data13 } in
        let st = AwaitClientFinished13 (client_fini, dec_ctx, st, log <+> raw) in
        Ok ({ state with machina = Server13 st ; session = `TLS13 sd :: state.session }, [])
      | Error e -> Error (`Error (`AuthenticationFailure e))
    end
  | (_ctx, cert_exts), auth ->
    (* TODO what to do with ctx? send through authenticator? *)
    (* TODO what to do with extensions? *)
    let certs = List.map fst cert_exts in
    let* peer_certificate, received_certificates, peer_certificate_chain, trust_anchor =
      validate_chain auth certs state.config.Config.ip None
    in
    let sd' = let common_session_data13 = {
        sd.common_session_data13 with
        received_certificates ;
        peer_certificate ;
        peer_certificate_chain ;
        trust_anchor
      } in
      { sd with common_session_data13 }
    in
    let st = AwaitClientCertificateVerify13 (sd', client_fini, dec_ctx, st, log <+> raw) in
    Ok ({ state with machina = Server13 st }, [])

let answer_client_certificate_verify state cv (sd : session_data13) client_fini dec_ctx st raw log =
  let tbs = Mirage_crypto.Hash.digest (Ciphersuite.hash13 sd.ciphersuite13) log in
  let* () =
    verify_digitally_signed `TLS_1_3
      ~context_string:"TLS 1.3, client CertificateVerify"
      state.config.Config.signature_algorithms cv tbs
      sd.common_session_data13.peer_certificate
  in
  let st = AwaitClientFinished13 (client_fini, dec_ctx, st, log <+> raw) in
  Ok ({ state with machina = Server13 st ; session = `TLS13 sd :: state.session }, [])

let answer_client_finished state fin client_fini dec_ctx st raw log =
  match state.session with
  | `TLS13 session :: rest ->
    let hash = Ciphersuite.hash13 session.ciphersuite13 in
    let data = finished hash client_fini log in
    let* () = guard (Cstruct.equal data fin) (`Fatal `BadFinished) in
    let* () =
      guard (Cstruct.length state.hs_fragment = 0)
        (`Fatal `HandshakeFragmentsNotEmpty)
    in
    let session' = match st, state.config.Config.ticket_cache with
      | None, _ | _, None -> session
      | Some st, Some cache ->
        let resumption_secret = Handshake_crypto13.resumption session.master_secret (log <+> raw) in
        let session = { session with resumption_secret } in
        let secret = Handshake_crypto13.res_secret hash resumption_secret st.nonce in
        let issued_at = cache.Config.timestamp () in
        let psk = { identifier = st.ticket ; obfuscation = st.age_add ; secret ; lifetime = st.lifetime ; early_data = state.config.Config.zero_rtt ; issued_at } in
        let epoch = epoch_of_session true None `TLS_1_3 (`TLS13 session) in
        cache.Config.ticket_granted psk epoch ;
        session
    in
    let state' = { state with machina = Server13 Established13 ; session = `TLS13 session' :: rest } in
    Ok (state', [ `Change_dec dec_ctx ])
  | _ -> Error (`Fatal `InvalidSession)

let handle_end_of_early_data state cf hs_ctx cc st buf log =
  let machina = AwaitClientFinished13 (cf, cc, st, log <+> buf) in
  match state.session with
  | `TLS13 s1 :: _ ->
    let session = `TLS13 { s1 with state = `Established } :: state.session in
    Ok ({ state with machina = Server13 machina ; session }, [ `Change_dec hs_ctx ])
  | _ ->
    Error (`Fatal `InvalidSession)

let handle_key_update state req =
  match state.session with
  | `TLS13 session :: _ ->
    let* () =
      guard (Cstruct.length state.hs_fragment = 0)
        (`Fatal `HandshakeFragmentsNotEmpty)
    in
    let client_app_secret, client_ctx =
      app_secret_n_1 session.master_secret session.client_app_secret
    in
    let session' = { session with client_app_secret } in
    let session', out = match req with
      | Packet.UPDATE_NOT_REQUESTED -> session', []
      | Packet.UPDATE_REQUESTED ->
        let server_app_secret, server_ctx =
          app_secret_n_1 session.master_secret session.server_app_secret
        in
        let ku = KeyUpdate Packet.UPDATE_NOT_REQUESTED in
        Tracing.hs ~tag:"handshake-out" ku ;
        let ku_raw = Writer.assemble_handshake ku in
        { session' with server_app_secret },
        [ `Record (Packet.HANDSHAKE, ku_raw); `Change_enc server_ctx ]
    in
    let session = `TLS13 session' :: state.session in
    let state' = { state with machina = Server13 Established13 ; session } in
    Ok (state', `Change_dec client_ctx :: out)
  | _ -> Error (`Fatal `InvalidSession)

let handle_handshake cs hs buf =
  let open Reader in
  let* handshake = map_reader_error (parse_handshake buf) in
  Tracing.hs ~tag:"handshake-in" handshake;
  match cs, handshake with
  | AwaitClientHelloHRR13, ClientHello ch ->
    answer_client_hello ~hrr:true hs ch buf
  | AwaitClientCertificate13 (sd, cf, cc, st, log), Certificate cert ->
    answer_client_certificate hs cert sd cf cc st buf log
  | AwaitClientCertificateVerify13 (sd, cf, cc, st, log), CertificateVerify cv ->
    answer_client_certificate_verify hs cv sd cf cc st buf log
  | AwaitClientFinished13 (cf, cc, st, log), Finished x ->
    answer_client_finished hs x cf cc st buf log
  | AwaitEndOfEarlyData13 (cf, hs_c, cc, st, log), EndOfEarlyData ->
    handle_end_of_early_data hs cf hs_c cc st buf log
  | Established13, KeyUpdate req ->
    handle_key_update hs req
  | _, hs -> Error (`Fatal (`UnexpectedHandshake hs))
