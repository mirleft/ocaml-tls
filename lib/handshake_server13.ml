open Utils

open State
open Core
open Handshake_common

open Handshake_crypto13

let answer_client_hello state ch raw log =
  (match client_hello_valid ch with
   | `Error e -> fail (`Fatal (`InvalidClientHello e))
   | `Ok -> return () ) >>= fun () ->

  (* TODO: if early_data 0RTT *)
  let ciphers =
    let open Ciphersuite in
    let supported =
      filter_map ~f:any_ciphersuite_to_ciphersuite ch.ciphersuites
    in
    List.filter ciphersuite_tls13 supported
  in

  ( match map_find ~f:(function `SignatureAlgorithms sa -> Some sa | _ -> None) ch.extensions with
    | None -> fail (`Fatal (`InvalidClientHello `NoSignatureAlgorithmsExtension))
    | Some sa -> return sa ) >>= fun sigalgs ->

  ( match map_find ~f:(function `SupportedGroups gs -> Some gs | _ -> None) ch.extensions with
    | None -> fail (`Fatal (`InvalidClientHello `NoSupportedGroupExtension))
    | Some gs -> return (filter_map ~f:Ciphersuite.any_group_to_group gs )) >>= fun groups ->

  ( match map_find ~f:(function `KeyShare ks -> Some ks | _ -> None) ch.extensions with
    | None -> fail (`Fatal (`InvalidClientHello `NoKeyShareExtension))
    | Some ks ->
       let f (g, ks) = match Ciphersuite.any_group_to_group g with
         | None -> None
         | Some g -> Some (g, ks)
       in
       return (filter_map ~f ks) ) >>= fun keyshares ->

  let my_psk, my_ciphers =
    let my_ciphers = List.filter Ciphersuite.ciphersuite_tls13 state.config.Config.ciphers in
    List.partition Ciphersuite.ciphersuite_psk my_ciphers
  in

  let base_server_hello ciphersuite extensions =
    { server_version = TLS_1_3 ;
      server_random = Nocrypto.Rng.generate 32 ;
      sessionid = None ;
      ciphersuite ;
      extensions ;
    }
  in

  let resumed_session =
    match map_find ~f:(function `PreSharedKey ids -> Some ids | _ -> None) ch.extensions with
    | None -> None
    | Some ids ->
      match
        List.filter (function None -> false | Some _ -> true)
          (List.map state.config.Config.psk_cache ids)
      with
      | x::_ -> x
      | [] -> None
  in

  (* now we should decide what to do, depending on client hello and config:
     * ECDHE-PSK: requires a shared ECDHE_PSK ciphersuite, and a ECDHE KeyShare
     * DHE-PSK: requires a shared DHE_PSK ciphersuite, and a DHE KeyShare
     * PSK: requires a shared PSK ciphersuite *)

  match resumed_session, first_match ciphers my_psk with
  | Some epoch, Some cipher ->
    let sh = base_server_hello cipher [`PreSharedKey epoch.psk_id] in
    let sh_raw = Writer.assemble_handshake (ServerHello sh) in

    Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake (ServerHello sh) ;

    let es = epoch.resumption_secret in
    let ss = es in

    let log = log <+> raw <+> sh_raw in
    let server_ctx, client_ctx = hs_ctx cipher log es in

    let ee = EncryptedExtensions [`Hostname] in
    let ee_raw = Writer.assemble_handshake ee in

    Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake ee ;

    let log = log <+> ee_raw in
    let master_secret = master_secret cipher es ss log in

    let f_data = finished cipher master_secret true log in
    let fin = Finished f_data in
    let fin_raw = Writer.assemble_handshake fin in

    Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake fin ;

    let log = log <+> fin_raw in
    let server_app_ctx, client_app_ctx = app_ctx cipher log master_secret in

    guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->

    let session =
      let s = session_of_epoch epoch in
      { s with client_random = ch.client_random ; server_random = sh.server_random ; client_version = ch.client_version ; ciphersuite = cipher ; master_secret = master_secret } in
    (* new state: one of AwaitClientCertificate13 , AwaitClientFinished13 *)
    let st = AwaitClientFinished13 (session, Some client_app_ctx, log) in
    ({ state with machina = Server13 st },
     [ `Record (Packet.HANDSHAKE, sh_raw) ;
       `Change_enc (Some server_ctx) ;
       `Change_dec (Some client_ctx) ;
       `Record (Packet.HANDSHAKE, ee_raw) ;
       `Record (Packet.HANDSHAKE, fin_raw) ;
       `Change_enc (Some server_app_ctx) ] )

  | _ ->
    ( match first_match ciphers my_ciphers with
      | Some x -> return x
      | None -> fail (`Error (`NoConfiguredCiphersuite ciphers))
    ) >>= fun cipher ->


    match first_match (List.map fst keyshares) state.config.Config.groups with
    | None when Cstruct.len log > 0 -> fail (`Fatal `InvalidMessage) (* already sent a hello retry request, not doing this game again *)
    | None ->
      ( match first_match groups state.config.Config.groups with
        | None -> fail (`Fatal `NoSupportedGroup)
        | Some group ->
          let hrr = { version = TLS_1_3 ;
                      ciphersuite = cipher ;
                      selected_group = group ;
                      extensions = [] }
          in
          let hrr_raw = Writer.assemble_handshake (HelloRetryRequest hrr) in
          let log = raw <+> hrr_raw in
          let st = AwaitClientHello13 (ch, hrr, log) in
          return ({ state with machina = Server13 st },
                  [ `Record (Packet.HANDSHAKE, hrr_raw) ]) )

    | Some group ->
      let _, keyshare = List.find (fun (g, _) -> g = group) keyshares in
      (* XXX: for-each ciphers there should be a suitable group (skipping for now since we only have DHE) *)
      (* XXX: check sig_algs for signatures in certificate chain *)

      (* if acceptable, do server hello *)
      let secret, public = Nocrypto.Dh.gen_key group in
      (match Nocrypto.Dh.shared group secret keyshare with
       | None -> fail (`Fatal `InvalidDH)
       | Some x -> return x) >>= fun es ->
      let ss = es in

      let sh = base_server_hello cipher [`KeyShare (group, public)]
      in
      let sh_raw = Writer.assemble_handshake (ServerHello sh) in

      let log = log <+> raw <+> sh_raw in
      let server_ctx, client_ctx = hs_ctx cipher log es in

      (* ONLY if client sent a `Hostname *)
      let ee = EncryptedExtensions [ `Hostname ] in
      (* TODO also max_fragment_length ; client_certificate_url ; trusted_ca_keys ; user_mapping ; client_authz ; server_authz ; cert_type ; use_srtp ; heartbeat ; alpn ; status_request_v2 ; signed_cert_timestamp ; client_cert_type ; server_cert_type *)
      let ee_raw = Writer.assemble_handshake ee in

      let crt, pr = match state.config.Config.own_certificates with
        | `Single (chain, priv) -> chain, priv
        | _ -> assert false
      in
      let certs = List.map X509.Encoding.cs_of_cert crt in
      let cert = Certificate (Writer.assemble_certificates_1_3 (Cstruct.create 0) certs) in
      let cert_raw = Writer.assemble_handshake cert in

      let log = Cstruct.concat [ log ; ee_raw ; cert_raw ] in
      signature TLS_1_3 ~context_string:"TLS 1.3, server CertificateVerify" log (Some sigalgs) state.config.Config.hashes pr >>= fun signed ->
      let cv = CertificateVerify signed in
      let cv_raw = Writer.assemble_handshake cv in

      let log = log <+> cv_raw in
      let master_secret = master_secret cipher es ss log in
      let resumption_secret = resumption_secret cipher master_secret log in

      let f_data = finished cipher master_secret true log in
      let fin = Finished f_data in
      let fin_raw = Writer.assemble_handshake fin in

      let log = log <+> fin_raw in
      let server_app_ctx, client_app_ctx = app_ctx cipher log master_secret in

      guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->

      let session = { empty_session with client_random = ch.client_random ; server_random = sh.server_random ; client_version = ch.client_version ; ciphersuite = cipher ; own_private_key = Some pr ; own_certificate =  crt ; master_secret = master_secret ; resumption_secret = resumption_secret } in
      (* new state: one of AwaitClientCertificate13 , AwaitClientFinished13 *)
      let st = AwaitClientFinished13 (session, Some client_app_ctx, log) in
      ({ state with machina = Server13 st },
       [ `Record (Packet.HANDSHAKE, sh_raw) ;
         `Change_enc (Some server_ctx) ;
         `Change_dec (Some client_ctx) ;
         `Record (Packet.HANDSHAKE, ee_raw) ;
         `Record (Packet.HANDSHAKE, cert_raw) ;
         `Record (Packet.HANDSHAKE, cv_raw) ;
         `Record (Packet.HANDSHAKE, fin_raw) ;
         `Change_enc (Some server_app_ctx) ] )

let answer_client_finished state fin (sd : session_data) dec_ctx log buf =
  let data = finished sd.ciphersuite sd.master_secret false log in
  guard (Cs.equal data fin) (`Fatal `BadFinished) >>= fun () ->
  guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->
  let ret, sd =
    (* only change dec if we're in handshake, also send out session ticket only just after handshake *)
    match dec_ctx with
    | None -> ([], sd)
    | Some cc ->
      let st, psk_id =
        let rand = Nocrypto.Rng.generate 48 in
        let buf = Writer.assemble_session_ticket_1_3 0l rand in
        (SessionTicket buf, rand)
      in
      let st_raw = Writer.assemble_handshake st in
      ([ `Change_dec (Some cc) ; `Record (Packet.HANDSHAKE, st_raw) ],
       { sd with psk_id })
  in
  ({ state with
     machina = Server13 Established13 ;
     session = sd :: state.session },
   ret)

let answer_client_hello_retry state oldch ch hrr log raw =
  (* ch = oldch + keyshare for hrr.selected_group (6.3.1.3) *)
  guard (oldch.client_version = ch.client_version) (`Fatal `InvalidMessage) >>= fun () ->
  guard (oldch.ciphersuites = ch.ciphersuites) (`Fatal `InvalidMessage) >>= fun () ->
  (* XXX: properly check that extensions are the same, plus a keyshare for the selected_group *)
  (* clients must send keyshare extension in any case (6.3.2.3), but may be empty *)
  guard (List.length oldch.extensions = List.length ch.extensions) (`Fatal `InvalidMessage) >>= fun () ->
  answer_client_hello state ch raw log (* XXX: TLS draft: restart hash? https://github.com/tlswg/tls13-spec/issues/104 *)

let handle_handshake cs hs buf =
  let open Reader in
  match parse_handshake buf with
  | Ok handshake ->
     (match cs, handshake with
      | AwaitClientHello13 (oldch, hrr, log), ClientHello ch ->
         answer_client_hello_retry hs oldch ch hrr log buf
      | AwaitClientCertificate13, Certificate _ -> assert false (* process C, move to CV *)
      | AwaitClientCertificateVerify13, CertificateVerify _ -> assert false (* validate CV *)
      | AwaitClientFinished13 (sd, cc, log), Finished x ->
         answer_client_finished hs x sd cc log buf
      | _, hs -> fail (`Fatal (`UnexpectedHandshake hs)) )
  | Error re -> fail (`Fatal (`ReaderError re))
