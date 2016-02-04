open Utils

open State
open Core
open Handshake_common
open Config

open Handshake_crypto13

let answer_server_hello state ch (sh : server_hello) secrets raw log =
  (* assume SH valid, version 1.3, extensions are subset *)
  guard (List.mem sh.ciphersuite state.config.ciphers) (`Fatal `InvalidServerHello) >>= fun () ->
  guard (Ciphersuite.ciphersuite_tls13 sh.ciphersuite) (`Fatal `InvalidServerHello) >>= fun () ->

  match Ciphersuite.kex13 sh.ciphersuite with
  | Ciphersuite.PSK ->
    ( match map_find ~f:(function `PreSharedKey psk -> Some psk | _ -> None) sh.extensions, state.config.Config.cached_session with
        | Some x, Some e ->
          guard (Cstruct.equal e.psk_id x) (`Fatal `InvalidServerHello) >>= fun () ->
          guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->

          let session =
            let s = session_of_epoch e in
            { s with client_random = ch.client_random ; server_random = sh.server_random ; client_version = ch.client_version ; ciphersuite = sh.ciphersuite } in

          let es = e.resumption_secret in

          let log = log <+> raw in
          let server_ctx, client_ctx = hs_ctx sh.ciphersuite log es in

          let st = AwaitServerEncryptedExtensions13 (session, sh.extensions, es, log) in
          ({ state with machina = Client13 st },
           [ `Change_enc (Some client_ctx) ;
             `Change_dec (Some server_ctx) ])
        | _ -> fail (`Fatal `InvalidServerHello) )
  | Ciphersuite.DHE_RSA ->
    ( match map_find ~f:(function `KeyShare ks -> Some ks | _ -> None) sh.extensions with
        | Some ks -> return ks
        | None -> fail (`Fatal `InvalidServerHello) ) >>= fun (group, keyshare) ->

    guard (List.mem group (List.map fst secrets)) (`Fatal `InvalidServerHello) >>= fun () ->
    guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >>= fun () ->

    let _, secret = List.find (fun (g, ks) -> g = group) secrets in

    let session = { empty_session with client_random = ch.client_random ; server_random = sh.server_random ; client_version = ch.client_version ; ciphersuite = sh.ciphersuite } in

    ( match Nocrypto.Dh.shared group secret keyshare with
      | None -> fail (`Fatal `InvalidDH)
      | Some x -> return x ) >|= fun shared ->

    let log = log <+> raw in
    let server_ctx, client_ctx = hs_ctx sh.ciphersuite log shared in
    let st = AwaitServerEncryptedExtensionsMaybeAuth13 (session, sh.extensions, shared, log) in
    ({ state with machina = Client13 st },
     [ `Change_enc (Some client_ctx) ;
       `Change_dec (Some server_ctx) ])

  | _ -> fail (`Fatal `InvalidServerHello)

(* called from handshake_client.ml *)
let answer_hello_retry_request state (ch : client_hello) hrr secrets raw log =
  guard (TLS_1_3 = hrr.version) (`Fatal `InvalidMessage) >>= fun () ->
  let sg = Ciphersuite.group_to_any_group hrr.selected_group in
  (match map_find ~f:(function `SupportedGroups gs -> Some gs | _ -> None) ch.extensions with
    | None -> fail (`Fatal `InvalidMessage)
    | Some gs -> guard (List.mem sg gs) (`Fatal `InvalidMessage)) >>= fun () ->
  guard (List.mem (Ciphersuite.ciphersuite_to_any_ciphersuite hrr.ciphersuite) ch.ciphersuites) (`Fatal `InvalidMessage) >>= fun () ->
  (match map_find ~f:(function `KeyShare ks -> Some ks | _ -> None) ch.extensions with
    | None -> fail (`Fatal `InvalidMessage)
    | Some ks ->
      guard (List.for_all (fun (g, _) -> g <> sg) ks) (`Fatal `InvalidMessage) >|= fun () ->
      let sec, share = Nocrypto.Dh.gen_key hrr.selected_group in
      (sec, `KeyShare (ks@[sg, share]))) >>= fun (sec, ks) ->
  let other_exts = List.filter (function `KeyShare _ -> false | _ -> true) ch.extensions in
  let new_ch = { ch with extensions = (other_exts @ [ks]) } in
  let new_ch_raw = Writer.assemble_handshake (ClientHello new_ch) in
  let st = AwaitServerHello13 (new_ch, [(hrr.selected_group, sec)], Cs.appends [ log ; raw ; new_ch_raw ]) in

  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake (ClientHello new_ch);

  return ({ state with machina = Client13 st }, [`Record (Packet.HANDSHAKE, new_ch_raw)])

let answer_encrypted_extensions_auth state session exts shared ee raw log =
  let st = AwaitServerFinishedMaybeAuth13 (session, exts @ ee, shared, log <+> raw) in
  return ({ state with machina = Client13 st }, [])

let answer_encrypted_extensions state session exts shared ee raw log =
  (* we can get CertificateRequest, ServerConfiguration, Certificate, Finished *)
  let st = AwaitServerFinished13 (session, exts @ ee, shared, log <+> raw) in
  return ({ state with machina = Client13 st }, [])

let answer_certificate state (session : session_data) exts shared certs raw log =
  let name = match state.config.peer_name with
    | None -> None | Some x -> Some (`Wildcard x)
  in
  validate_chain state.config.authenticator certs name >>=
  fun (peer_certificate, received_certificates, peer_certificate_chain, trust_anchor) ->
  (* XXX: do we need keytype and usage as well? *)
  let session = { session with received_certificates ; peer_certificate_chain ; peer_certificate ; trust_anchor } in
  let st = AwaitServerCertificateVerify13 (session, exts, shared, log <+> raw) in
  return ({ state with machina = Client13 st }, [])

let answer_certificate_verify (state : handshake_state) (session : session_data) exts shared cv raw log =
  verify_digitally_signed state.protocol_version ~context_string:"TLS 1.3, server CertificateVerify" state.config.hashes cv log session.peer_certificate >>= fun () ->
  let st = AwaitServerFinished13 (session, exts, shared, log <+> raw) in
  return ({ state with machina = Client13 st }, [])

let answer_finished state (session : session_data) exts shared fin raw log =
  let master_secret = master_secret session.ciphersuite shared shared log in
  let resumption_secret = resumption_secret session.ciphersuite master_secret log in

  let cfin = finished session.ciphersuite master_secret true log in
  guard (Cs.equal fin cfin) (`Fatal `BadFinished) >>= fun () ->
  guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->

  let log = log <+> raw in
  let server_app_ctx, client_app_ctx = app_ctx session.ciphersuite log master_secret in
  let myfin = finished session.ciphersuite master_secret false log in
  let mfin = Writer.assemble_handshake (Finished myfin) in
  let sd = { session with master_secret ; resumption_secret } in
  let machina = Client13 Established13 in

  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake (Finished myfin);

  ({ state with machina ; session = sd :: state.session },
   [ `Change_dec (Some server_app_ctx) ;
     `Record (Packet.HANDSHAKE, mfin) ;
     `Change_enc (Some client_app_ctx) ])

let answer_session_ticket state _lifetime psk_id =
  (* XXX: do sth with lifetime *)
  (match state.session with
   | [] -> fail (`Fatal `InvalidMessage)
   | s::xs -> return ({ s with psk_id } :: xs)) >>= fun session ->
  return ({ state with session }, [])

let handle_handshake cs hs buf =
  let open Reader in
  match parse_handshake buf with
  | Ok handshake ->
     Tracing.sexpf ~tag:"handshake-in" ~f:sexp_of_tls_handshake handshake;
     (match cs, handshake with
      | AwaitServerHello13 (ch, secrets, log), ServerHello sh ->
         answer_server_hello hs ch sh secrets buf log
      | AwaitServerEncryptedExtensions13 (sd, exts, shared, log), EncryptedExtensions ee ->
         answer_encrypted_extensions hs sd exts shared ee buf log
      | AwaitServerEncryptedExtensionsMaybeAuth13 (sd, exts, shared, log), EncryptedExtensions ee ->
         answer_encrypted_extensions_auth hs sd exts shared ee buf log
      | AwaitServerFinishedMaybeAuth13 (sd, exts, shared, log), CertificateRequest _ -> assert false (* process CR *)
      | AwaitServerFinishedMaybeAuth13 (sd, exts, shared, log), ServerConfiguration _ -> assert false (* preserve SC *)
      | AwaitServerFinishedMaybeAuth13 (sd, exts, shared, log), Certificate cs ->
        (match parse_certificates_1_3 cs with
         | Ok (con, cs) ->
           guard (Cs.null con) (`Fatal `InvalidMessage) >>= fun () ->
           answer_certificate hs sd exts shared cs buf log
         | Error re -> fail (`Fatal (`ReaderError re)))
      | AwaitServerCertificateVerify13 (sd, exts, shared, log), CertificateVerify cv ->
         answer_certificate_verify hs sd exts shared cv buf log
      | AwaitServerFinished13 (sd, exts, shared, log), Finished fin ->
         answer_finished hs sd exts shared fin buf log
      | AwaitServerFinishedMaybeAuth13 (sd, exts, shared, log), Finished fin ->
         answer_finished hs sd exts shared fin buf log
      | Established13, SessionTicket se ->
        (match parse_session_ticket_1_3 se with
         | Ok (lifetime, psk_id) -> answer_session_ticket hs lifetime psk_id
         | Error re -> fail (`Fatal (`ReaderError re)))
      | Established13, CertificateRequest _ -> assert false (* maybe send out C, CV, F *)
      | _, hs -> fail (`Fatal (`UnexpectedHandshake hs)))
  | Error re -> fail (`Fatal (`ReaderError re))
