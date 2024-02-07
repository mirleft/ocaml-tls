open Core
open State

type state = State.state

type client_hello_errors = State.client_hello_errors
type error = State.error
type fatal = State.fatal
type failure = State.failure

let alert_of_authentication_failure = function
  | `LeafCertificateExpired _ -> Packet.CERTIFICATE_EXPIRED
  | _ -> Packet.BAD_CERTIFICATE

let alert_of_error = function
  | `NoConfiguredVersions _ -> Packet.PROTOCOL_VERSION
  | `NoConfiguredCiphersuite _ -> Packet.HANDSHAKE_FAILURE
  | `NoConfiguredSignatureAlgorithm _ -> Packet.HANDSHAKE_FAILURE
  | `AuthenticationFailure err -> alert_of_authentication_failure err
  | `NoMatchingCertificateFound _ -> Packet.UNRECOGNIZED_NAME
  | `NoCertificateConfigured -> Packet.HANDSHAKE_FAILURE
  | `CouldntSelectCertificate -> Packet.HANDSHAKE_FAILURE

let alert_of_fatal = function
  | `NoSecureRenegotiation -> Packet.HANDSHAKE_FAILURE
  | `NoSupportedGroup -> Packet.HANDSHAKE_FAILURE
  | `MACUnderflow -> Packet.BAD_RECORD_MAC
  | `MACMismatch -> Packet.BAD_RECORD_MAC
  | `RecordOverflow _ -> Packet.RECORD_OVERFLOW
  | `UnknownRecordVersion _ -> Packet.PROTOCOL_VERSION
  | `UnknownContentType _ -> Packet.UNEXPECTED_MESSAGE
  | `ReaderError (Reader.UnknownVersion _) -> Packet.PROTOCOL_VERSION
  | `ReaderError (Reader.TrailingBytes _) -> Packet.UNEXPECTED_MESSAGE
  | `ReaderError Reader.Underflow -> Packet.DECODE_ERROR
  | `ReaderError _ -> Packet.ILLEGAL_PARAMETER
  | `CannotHandleApplicationDataYet -> Packet.UNEXPECTED_MESSAGE
  | `NoHeartbeat -> Packet.UNEXPECTED_MESSAGE
  | `BadRecordVersion _ -> Packet.PROTOCOL_VERSION
  | `InvalidRenegotiation -> Packet.HANDSHAKE_FAILURE
  | `InvalidServerHello -> Packet.UNSUPPORTED_EXTENSION
  | `InvalidRenegotiationVersion _ -> Packet.HANDSHAKE_FAILURE
  | `NoCertificateReceived -> Packet.HANDSHAKE_FAILURE
  | `NoCertificateVerifyReceived -> Packet.HANDSHAKE_FAILURE
  | `NotRSACertificate -> Packet.BAD_CERTIFICATE
  | `InvalidCertificateUsage -> Packet.BAD_CERTIFICATE
  | `InvalidCertificateExtendedUsage -> Packet.BAD_CERTIFICATE
  | `NoVersions _ -> Packet.PROTOCOL_VERSION
  | `InsufficientDH -> Packet.INSUFFICIENT_SECURITY
  | `InvalidDH -> Packet.ILLEGAL_PARAMETER
  | `BadECDH _ -> Packet.ILLEGAL_PARAMETER
  | `BadFinished -> Packet.DECRYPT_ERROR
  | `HandshakeFragmentsNotEmpty -> Packet.HANDSHAKE_FAILURE
  | `InvalidSession -> Packet.HANDSHAKE_FAILURE
  | `UnexpectedCCS -> Packet.UNEXPECTED_MESSAGE
  | `UnexpectedHandshake _ -> Packet.UNEXPECTED_MESSAGE
  | `SignatureVerificationFailed _ -> Packet.HANDSHAKE_FAILURE
  | `SigningFailed _ -> Packet.HANDSHAKE_FAILURE
  | `KeyTooSmall -> Packet.INSUFFICIENT_SECURITY
  | `BadCertificateChain -> Packet.BAD_CERTIFICATE
  | `InvalidClientHello `NoSignatureAlgorithmsExtension
  | `InvalidClientHello `NoKeyShareExtension
  | `InvalidClientHello `NoSupportedGroupExtension -> Packet.MISSING_EXTENSION
  | `InvalidClientHello (`NotSetSupportedGroup _)
  | `InvalidClientHello (`NotSetKeyShare _)
  | `InvalidClientHello (`NotSubsetKeyShareSupportedGroup _) -> Packet.ILLEGAL_PARAMETER
  | `InvalidClientHello _ -> Packet.HANDSHAKE_FAILURE
  | `InappropriateFallback -> Packet.INAPPROPRIATE_FALLBACK
  | `NoApplicationProtocol -> Packet.NO_APPLICATION_PROTOCOL
  | `HelloRetryRequest -> Packet.HANDSHAKE_FAILURE (* TODO check *)
  | `InvalidMessage -> Packet.HANDSHAKE_FAILURE
  | `Toomany0rttbytes -> Packet.UNEXPECTED_MESSAGE
  | `MissingContentType -> Packet.UNEXPECTED_MESSAGE
  | `Downgrade12 | `Downgrade11 -> Packet.ILLEGAL_PARAMETER
  | `WriteHalfClosed -> Packet.UNEXPECTED_MESSAGE

let alert_of_failure = function
  | `Error x -> Packet.FATAL, alert_of_error x
  | `Fatal x -> Packet.FATAL, alert_of_fatal x
  | `Alert _ -> Packet.WARNING, Packet.CLOSE_NOTIFY

let pp_failure = State.pp_failure

let string_of_failure = Fmt.to_to_string pp_failure

type ret =
  (state * [ `Eof ] option
   * [ `Response of Cstruct.t option ]
   * [ `Data of Cstruct.t option ],
   failure * [ `Response of Cstruct.t ]) result

let new_state config role =
  let handshake_state = match role with
    | `Client -> Client ClientInitial
    | `Server -> Server AwaitClientHello
  in
  let version = max_protocol_version Config.(config.protocol_versions) in
  let handshake = {
    session          = [] ;
    protocol_version = version ;
    early_data_left  = 0l ;
    machina          = handshake_state ;
    config           = config ;
    hs_fragment      = Cstruct.create 0 ;
  }
  in
  {
    handshake = handshake ;
    decryptor = None ;
    encryptor = None ;
    fragment  = Cstruct.empty ;
    read_closed = false ;
    write_closed = false ;
  }

type raw_record = tls_hdr * Cstruct.t

let pp_raw_record ppf (hdr, data) =
  Fmt.pf ppf "%a (%u bytes data)" pp_tls_hdr hdr (Cstruct.length data)

let pp_frame ppf (ty, data) =
  Fmt.pf ppf "%a (%u bytes data)" Packet.pp_content_type ty
    (Cstruct.length data)

(* well-behaved pure encryptor *)
let encrypt (version : tls_version) (st : crypto_state) ty buf =
  match st with
  | None -> (st, ty, buf)
  | Some ctx ->
     match version with
     | `TLS_1_3 ->
        (match ctx.cipher_st with
         | AEAD c ->
            let buf =
              let t = Cstruct.create 1 in
              Cstruct.set_uint8 t 0 (Packet.content_type_to_int ty) ;
              buf <+> t
            in
            let nonce = Crypto.aead_nonce c.nonce ctx.sequence in
            let adata = Crypto.adata_1_3 (Cstruct.length buf + Crypto.tag_len c.cipher) in
            let buf = Crypto.encrypt_aead ~cipher:c.cipher ~adata ~key:c.cipher_secret ~nonce buf in
            (Some { ctx with sequence = Int64.succ ctx.sequence }, Packet.APPLICATION_DATA, buf)
         | _ -> assert false)
     | _ ->
        let pseudo_hdr =
          let seq = ctx.sequence
          and ver = pair_of_tls_version version
        in
        Crypto.pseudo_header seq ty ver (Cstruct.length buf)
        in
        let to_encrypt mac mac_k =
          let signature = Crypto.mac mac mac_k pseudo_hdr buf in
          buf <+> signature
        in
        let c_st, enc =
          match ctx.cipher_st with
          | CBC c ->
             let enc iv =
               let to_encrypt = to_encrypt c.hmac c.hmac_secret in
               Crypto.encrypt_cbc ~cipher:c.cipher ~key:c.cipher_secret ~iv to_encrypt
             in
             ( match c.iv_mode with
               | Random_iv ->
                  let iv = Mirage_crypto_rng.generate (Crypto.cbc_block c.cipher) in
                  let m, _ = enc iv in
                  (CBC c, iv <+> m)
               | Iv iv ->
                  let m, iv' = enc iv in
                  (CBC { c with iv_mode = Iv iv' }, m) )

          | AEAD c ->
            if c.explicit_nonce then
              let explicit_nonce = Crypto.sequence_buf ctx.sequence in
              let nonce = c.nonce <+> explicit_nonce
              in
              let msg =
                Crypto.encrypt_aead ~cipher:c.cipher ~key:c.cipher_secret ~nonce ~adata:pseudo_hdr buf
              in
              (AEAD c, explicit_nonce <+> msg)
            else
              (* RFC 7905: no explicit nonce, instead TLS 1.3 construction is adapted *)
              let nonce = Crypto.aead_nonce c.nonce ctx.sequence in
              let msg =
                Crypto.encrypt_aead ~cipher:c.cipher ~key:c.cipher_secret ~nonce ~adata:pseudo_hdr buf
              in
              (AEAD c, msg)
        in
        (Some { sequence = Int64.succ ctx.sequence ; cipher_st = c_st }, ty, enc)

(* well-behaved pure decryptor *)
let verify_mac sequence mac mac_k ty ver decrypted =
  let macstart = Cstruct.length decrypted - Mirage_crypto.Hash.digest_size mac in
  let* () = guard (macstart >= 0) (`Fatal `MACUnderflow) in
  let (body, mmac) = Cstruct.split decrypted macstart in
  let cmac =
    let ver = pair_of_tls_version ver in
    let hdr = Crypto.pseudo_header sequence ty ver (Cstruct.length body) in
    Crypto.mac mac mac_k hdr body in
  let* () = guard (Cstruct.equal cmac mmac) (`Fatal `MACMismatch) in
  Ok body


let decrypt ?(trial = false) (version : tls_version) (st : crypto_state) ty buf =

  let compute_mac seq mac mac_k buf = verify_mac seq mac mac_k ty version buf in
  (* hmac is computed in this failure branch from the encrypted data, in the
     successful branch it is decrypted - padding (which is smaller equal than
     encrypted data) *)
  (* This comment is borrowed from miTLS, but applies here as well: *)
  (* We implement standard mitigation for padding oracles. Still, we note a
     small timing leak here: The time to verify the mac is linear in the
     plaintext length. *)
  (* defense against http://lasecwww.epfl.ch/memo/memo_ssl.shtml 1) in
     https://www.openssl.org/~bodo/tls-cbc.txt *)
  let mask_decrypt_failure seq mac mac_k =
    let* _ = compute_mac seq mac mac_k buf in
    Error (`Fatal `MACMismatch)
  in

  let dec ctx =
    let seq = ctx.sequence in
    match ctx.cipher_st with
    | CBC c ->
       let dec iv buf =
         match Crypto.decrypt_cbc ~cipher:c.cipher ~key:c.cipher_secret ~iv buf with
         | None ->
            mask_decrypt_failure seq c.hmac c.hmac_secret
         | Some (dec, iv') ->
            let* msg = compute_mac seq c.hmac c.hmac_secret dec in
            Ok (msg, iv')
       in
       ( match c.iv_mode with
         | Iv iv ->
            let* msg, iv' = dec iv buf in
            Ok (CBC { c with iv_mode = Iv iv' }, msg)
         | Random_iv ->
            if Cstruct.length buf < Crypto.cbc_block c.cipher then
              Error (`Fatal `MACUnderflow)
            else
              let iv, buf = Cstruct.split buf (Crypto.cbc_block c.cipher) in
              let* msg, _ = dec iv buf in
              Ok (CBC c, msg) )

    | AEAD c ->
      if c.explicit_nonce then
        let explicit_nonce_len = 8 in
        if Cstruct.length buf < explicit_nonce_len then
          Error (`Fatal `MACUnderflow)
        else
          let explicit_nonce, buf = Cstruct.split buf explicit_nonce_len in
          let adata =
            let ver = pair_of_tls_version version in
            Crypto.pseudo_header seq ty ver (Cstruct.length buf - Crypto.tag_len c.cipher)
          and nonce = c.nonce <+> explicit_nonce
          in
          match Crypto.decrypt_aead ~cipher:c.cipher ~key:c.cipher_secret ~nonce ~adata buf with
          | None -> Error (`Fatal `MACMismatch)
          | Some x -> Ok (AEAD c, x)
      else
        (* RFC 7905: no explicit nonce, instead TLS 1.3 construction is adapted *)
        let adata =
          let ver = pair_of_tls_version version in
          Crypto.pseudo_header seq ty ver (Cstruct.length buf - Crypto.tag_len c.cipher)
        and nonce = Crypto.aead_nonce c.nonce seq
        in
        (match Crypto.decrypt_aead ~adata ~cipher:c.cipher ~key:c.cipher_secret ~nonce buf with
         | None -> Error (`Fatal `MACMismatch)
         | Some x -> Ok (AEAD c, x))
  in
  match st, version with
  | None, _ when ty = Packet.APPLICATION_DATA ->
    (* the server can end up in the situation:
       CH [+early_data +key_share] ; APP_DATA  ---->
           <--- HRR [+key_share] (does not install a decryptor,
                                  early data now disallowed)
       CH [+key_share] ----->
       the APP_DATA above cannot be decrypted or used, so we drop it.
    *)
    Ok (None, Cstruct.empty, Packet.APPLICATION_DATA)
  | None, _ -> Ok (st, buf, ty)
  | Some ctx, `TLS_1_3 ->
    (match ty with
     | Packet.CHANGE_CIPHER_SPEC -> Ok (st, buf, ty)
     | Packet.APPLICATION_DATA ->
       (match ctx.cipher_st with
        | AEAD c ->
          let nonce = Crypto.aead_nonce c.nonce ctx.sequence in
          let unpad x =
            let rec eat = function
              | -1 -> Error (`Fatal `MissingContentType)
              | idx -> match Cstruct.get_uint8 x idx with
                | 0 -> eat (pred idx)
                | n -> match Packet.int_to_content_type n with
                  | Some ct -> Ok (Cstruct.sub x 0 idx, ct)
                  | None -> Error (`Fatal `MACUnderflow) (* TODO better error? *)
            in
            eat (pred (Cstruct.length x))
          in
          let adata = Crypto.adata_1_3 (Cstruct.length buf) in
          (match Crypto.decrypt_aead ~adata ~cipher:c.cipher ~key:c.cipher_secret ~nonce buf with
           | None ->
             if trial then
               Ok (Some ctx, Cstruct.empty, Packet.APPLICATION_DATA)
             else
               Error (`Fatal `MACMismatch)
           | Some x ->
             let* data, ty = unpad x in
             Ok (Some { ctx with sequence = Int64.succ ctx.sequence }, data, ty))
        | _ -> Error (`Fatal `InvalidMessage))
     | _ -> Error (`Fatal `InvalidMessage))
  | Some ctx, _ ->
    let* st', msg = dec ctx in
    let ctx' = { cipher_st = st' ; sequence = Int64.succ ctx.sequence } in
    Ok (Some ctx', msg, ty)

(* party time *)
let rec separate_records : Cstruct.t -> ((tls_hdr * Cstruct.t) list * Cstruct.t, failure) result
= fun buf ->
  let open Reader in
  match parse_record buf with
  | Ok (`Fragment b) -> Ok ([], b)
  | Ok (`Record (packet, fragment)) ->
    let* tl, frag = separate_records fragment in
    Ok (packet :: tl, frag)
  | Error (Overflow x) ->
    Tracing.cs ~tag:"buf-in" buf ;
    Error (`Fatal (`RecordOverflow x))
  | Error (UnknownVersion v) ->
    Tracing.cs ~tag:"buf-in" buf ;
    Error (`Fatal (`UnknownRecordVersion v))
  | Error (UnknownContent c) ->
    Tracing.cs ~tag:"buf-in" buf ;
    Error (`Fatal (`UnknownContentType c))
  | Error e ->
    Tracing.cs ~tag:"buf-in" buf ;
    Error (`Fatal (`ReaderError e))


let encrypt_records encryptor version records =
  let rec split = function
    | [] -> []
    | (t1, a) :: xs when Cstruct.length a >= 1 lsl 14 ->
      let fst, snd = Cstruct.split a (1 lsl 14) in
      (t1, fst) :: split ((t1, snd) :: xs)
    | x::xs -> x :: split xs

  and crypt st = function
    | []            -> (st, [])
    | (ty, buf)::rs ->
        let (st, ty, enc) = encrypt version st ty buf in
        let (st, encs) = crypt st rs in
        (st, (ty, enc) :: encs)
  in
  crypt encryptor (split records)

module Alert = struct
  (* The alert protocol:
     - receiving a close_notify leads to eof (never read() any further data)
     - any fatal alert leads to sending a close_notify and state is closed
  *)

  open Packet

  let make ?level typ = (ALERT, Writer.assemble_alert ?level typ)

  let close_notify = make ~level:WARNING CLOSE_NOTIFY

  let handle buf =
    let* alert = map_reader_error (Reader.parse_alert buf) in
    let _, a_type = alert in
    Tracing.debug (fun m -> m "alert-in %a" pp_alert alert) ;
    match a_type with
    | CLOSE_NOTIFY | USER_CANCELED -> Ok true
    | _ -> Error (`Alert a_type)
end

let hs_can_handle_appdata s =
  (* When is a TLS session up for some application data?
     - initial handshake must be finished!
     - renegotiation must not be in progress
     --> thus only ok for Established
     - but ok if server sent a HelloRequest and can get first some appdata then ClientHello
     --> or converse: client sent ClientHello, waiting for ServerHello *)
  (* turns out, rules in 1.3 are slightly different -- server may send appdata after its first flight!
     this means in any observable state! (apart from when a HRR was sent) *)
  match s.machina with
  | Server13 AwaitClientHelloHRR13 -> false
  | Server Established | Server AwaitClientHelloRenegotiate | Server13 _
  | Client Established | Client AwaitServerHelloRenegotiate _ | Client13 Established13 -> true
  | _ -> false

let early_data s =
  match s.machina with
  | Server13 AwaitClientHelloHRR13
  | Server13 (AwaitEndOfEarlyData13 _) | Server13 (AwaitClientFinished13 _)
  | Server13 (AwaitClientCertificate13 _) | Server13 (AwaitClientCertificateVerify13 _) -> true
  | _ -> false

let rec separate_handshakes buf =
  match Reader.parse_handshake_frame buf with
  | None, rest -> [], rest
  | Some hs, rest ->
    let rt, frag = separate_handshakes rest in
    hs :: rt, frag

let handle_change_cipher_spec = function
  | Client cs -> Handshake_client.handle_change_cipher_spec cs
  | Server ss -> Handshake_server.handle_change_cipher_spec ss
  (* D.4: the client may send a CCS before its second flight
          (before second ClientHello or encrypted handshake flight)
          the server may send it immediately after its first handshake message
          (ServerHello or HelloRetryRequest) *)
  | Client13 (AwaitServerEncryptedExtensions13 _)
  | Client13 (AwaitServerHello13 _)
  | Server13 AwaitClientHelloHRR13
  | Server13 (AwaitClientCertificate13 _)
  | Server13 (AwaitClientFinished13 _) -> (fun s _ -> Ok (s, []))
  | _ -> (fun _ _ -> Error (`Fatal `UnexpectedCCS))

and handle_handshake = function
  | Client cs -> Handshake_client.handle_handshake cs
  | Server ss -> Handshake_server.handle_handshake ss
  | Client13 cs -> Handshake_client13.handle_handshake cs
  | Server13 ss -> Handshake_server13.handle_handshake ss

let non_empty cs =
  if Cstruct.length cs = 0 then None else Some cs

let handle_packet hs buf = function
(* RFC 5246 -- 6.2.1.:
   Implementations MUST NOT send zero-length fragments of Handshake,
   Alert, or ChangeCipherSpec content types.  Zero-length fragments of
   Application data MAY be sent as they are potentially useful as a
   traffic analysis countermeasure.
 *)

  | Packet.ALERT ->
    let* eof = Alert.handle buf in
    Ok (hs, [], None, eof)

  | Packet.APPLICATION_DATA ->
    if hs_can_handle_appdata hs || (early_data hs && Cstruct.length hs.hs_fragment = 0) then
      (Tracing.cs ~tag:"application-data-in" buf;
       Ok (hs, [], non_empty buf, false))
    else
      Error (`Fatal `CannotHandleApplicationDataYet)

  | Packet.CHANGE_CIPHER_SPEC ->
     let* hs, items = handle_change_cipher_spec hs.machina hs buf in
     Ok (hs, items, None, false)

  | Packet.HANDSHAKE ->
     let hss, hs_fragment = separate_handshakes (hs.hs_fragment <+> buf) in
     let hs = { hs with hs_fragment } in
     let* hs, items =
       List.fold_left (fun acc raw ->
           let* hs, items = acc in
           let* hs', items' = handle_handshake hs.machina hs raw in
           Ok (hs', items @ items'))
         (Ok (hs, [])) hss
     in
     Ok (hs, items, None, false)

let decrement_early_data hs ty buf =
  let bytes left cipher =
    let count = Cstruct.length buf - fst (Ciphersuite.kn_13 (Ciphersuite.privprot13 cipher)) in
    let left' = Int32.sub left (Int32.of_int count) in
    if left' < 0l then Error (`Fatal `Toomany0rttbytes) else Ok left'
  in
  if ty = Packet.APPLICATION_DATA && early_data hs then
    let cipher = match hs.session with
      | `TLS13 sd::_ -> sd.ciphersuite13
      | _ -> `AES_128_GCM_SHA256
      (* TODO assert and ensure that all early_data states have a cipher  *)
    in
    let* early_data_left = bytes hs.early_data_left cipher in
    Ok { hs with early_data_left }
  else
    Ok hs

(* the main thingy *)
let handle_raw_record state (hdr, buf as record : raw_record) =

  Tracing.debug (fun m -> m "record-in %a" pp_raw_record record) ;
  let hs = state.handshake in
  let version = hs.protocol_version in
  let* () =
    match hs.machina, version with
    | Client (AwaitServerHello _), _ -> Ok ()
    | Server AwaitClientHello, _ -> Ok ()
    | Server13 AwaitClientHelloHRR13, _ -> Ok ()
    | _, `TLS_1_3 -> guard (hdr.version = `TLS_1_2) (`Fatal (`BadRecordVersion hdr.version))
    | _, v -> guard (version_eq hdr.version v) (`Fatal (`BadRecordVersion hdr.version))
  in
  let trial = match hs.machina with
    | Server13 (AwaitEndOfEarlyData13 _) | Server13 Established13 -> false
    | Server13 _ -> hs.early_data_left > 0l && Cstruct.length hs.hs_fragment = 0
    | _ -> false
  in
  let* dec_st, dec, ty = decrypt ~trial version state.decryptor hdr.content_type buf in
  let* handshake = decrement_early_data hs ty buf in
  Tracing.debug (fun m -> m "frame-in %a" pp_frame (ty, dec)) ;
  let* handshake, items, data, read_closed = handle_packet handshake dec ty in
  let encryptor, decryptor, encs =
    List.fold_left (fun (enc, dec, es) -> function
      | `Change_enc enc' -> (Some enc', dec, es)
      | `Change_dec dec' -> (enc, Some dec', es)
      | `Record r       ->
         Tracing.debug (fun m -> m "frame-out %a" pp_frame r) ;
         let (enc', encbuf) = encrypt_records enc handshake.protocol_version [r] in
         (enc', dec, es @ encbuf))
    (state.encryptor, dec_st, [])
    items
  in
  List.iter (fun f -> Tracing.debug (fun m -> m "record-out %a" pp_frame f)) encs ;
  let read_closed = read_closed || state.read_closed in
  let state' = { state with handshake ; encryptor ; decryptor ; read_closed } in
  Ok (state', encs, data)

let maybe_app a b = match a, b with
  | Some x, Some y -> Some (x <+> y)
  | Some x, None   -> Some x
  | None  , Some y -> Some y
  | None  , None   -> None

let assemble_records (version : tls_version) rs =
  let version = match version with `TLS_1_3 -> `TLS_1_2 | x -> x in
  Cstruct.concat (List.map (Writer.assemble_hdr version) rs)

(* main entry point *)
let handle_tls state buf =
  Tracing.cs ~tag:"wire-in" buf ;

  let rec handle_records st = function
    | []    -> Ok (st, [], None)
    | r::rs ->
      let* st, raw_rs, data = handle_raw_record st r in
      let* st', raw_rs', data' = handle_records st rs in
      Ok (st', raw_rs @ raw_rs', maybe_app data data')
  in
  match
    let* in_records, fragment = separate_records (state.fragment <+> buf) in
    let* state', out_records, data = handle_records state in_records in
    let version = state'.handshake.protocol_version in
    let resp = match out_records with
      | [] -> None
      | _  ->
        let out = assemble_records version out_records in
        Tracing.cs ~tag:"wire-out" out ;
        Some out
    in
    Ok ({ state' with fragment }, resp, data)
  with
  | Ok (state, resp, data) ->
      let res =
        if state.read_closed then begin
          Tracing.debug (fun m -> m "eof-out") ;
          Some `Eof
        end else
          None
      in
      (* Tracing.sexpf ~tag:"state-out" ~f:sexp_of_state state ; *)
      Ok (state, res, `Response resp, `Data data)
  | Error x ->
      let version = state.handshake.protocol_version in
      let level, alert = alert_of_failure x in
      let record  = Alert.make ~level alert in
      let _, enc = encrypt_records state.encryptor version [record] in
      let resp = assemble_records version enc in
      Tracing.debug (fun m -> m "fail-alert-out %a" Packet.pp_alert (Packet.FATAL, alert)) ;
      Tracing.debug (fun m -> m "failure %a" pp_failure x) ;
      Error (x, `Response resp)

let send_records (st : state) records =
  let version = st.handshake.protocol_version in
  List.iter (fun f -> Tracing.debug (fun m -> m "frame-out %a" pp_frame f)) records ;
  let (encryptor, encs) =
    encrypt_records st.encryptor version records in
  List.iter (fun f -> Tracing.debug (fun m -> m "record-out %a" pp_frame f)) encs ;
  let data = assemble_records version encs in
  Tracing.cs ~tag:"wire-out" data ;
  ({ st with encryptor }, data)

let handshake_in_progress s = match s.handshake.machina with
  | Client Established | Server Established -> false
  | Client13 Established13 | Server13 Established13 -> false
  | _ -> true

(* entry for user data *)
let send_application_data st css =
  if st.write_closed || not (hs_can_handle_appdata st.handshake) then
    None
  else begin
    List.iter (fun cs -> Tracing.cs ~tag:"application-data-out" cs) css ;
    let datas = match st.encryptor with
      (* Mitigate implicit IV in CBC mode: prepend empty fragment *)
      | Some { cipher_st = CBC { iv_mode = Iv _ ; _ } ; _ } -> Cstruct.create 0 :: css
      | _                                                   -> css
    in
    let ty = Packet.APPLICATION_DATA in
    let data = List.map (fun cs -> (ty, cs)) datas in
    Some (send_records st data)
  end

let send_close_notify st =
  let st = { st with write_closed = true } in
  send_records st [Alert.close_notify]

let reneg ?authenticator ?acceptable_cas ?cert st =
  if st.write_closed || st.read_closed then
    (* this is a full handshake (with messages from both sides), thus if either
       direction has closed the flow, the reneg won't succeed *)
    None
  else
    let config = st.handshake.config in
    let config = Option.fold ~none:config ~some:(Config.with_authenticator config) authenticator in
    let config = Option.fold ~none:config ~some:(Config.with_acceptable_cas config) acceptable_cas in
    let config = Option.fold ~none:config ~some:(Config.with_own_certificates config) cert in
    let hs = { st.handshake with config } in
    match hs.machina with
    | Server Established ->
      ( match Handshake_server.hello_request hs with
        | Ok (handshake, [`Record hr]) -> Some (send_records { st with handshake } [hr])
        | _ -> None )
    | Client Established ->
      ( match Handshake_client.answer_hello_request hs with
        | Ok (handshake, [`Record ch]) -> Some (send_records { st with handshake } [ch])
        | _ -> None )
    | _ -> None

let key_update ?(request = true) state =
  if state.write_closed then
    Error (`Fatal `WriteHalfClosed)
  else
    let* state', out = Handshake_common.output_key_update ~request state in
    let _, outbuf = send_records state [out] in
    Ok (state', outbuf)

let client config =
  let config = Config.of_client config in
  let state = new_state config `Client in
  let dch, _version, secrets = Handshake_client.default_client_hello config in
  let ciphers, extensions = match config.Config.protocol_versions with
      (* from RFC 5746 section 3.3:
   Both the SSLv3 and TLS 1.0/TLS 1.1 specifications require
   implementations to ignore data following the ClientHello (i.e.,
   extensions) if they do not understand it. However, some SSLv3 and
   TLS 1.0 implementations incorrectly fail the handshake in such a
   case.  This means that clients that offer the "renegotiation_info"
   extension may encounter handshake failures.  In order to enhance
   compatibility with such servers, this document defines a second
   signaling mechanism via a special Signaling Cipher Suite Value (SCSV)
   "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", with code point {0x00, 0xFF}.
   This SCSV is not a true cipher suite (it does not correspond to any
   valid set of algorithms) and cannot be negotiated.  Instead, it has
   the same semantics as an empty "renegotiation_info" extension, as
   described in the following sections.  Because SSLv3 and TLS
   implementations reliably ignore unknown cipher suites, the SCSV may
   be safely sent to any server. *)
    | (_, `TLS_1_0) -> ([Packet.TLS_EMPTY_RENEGOTIATION_INFO_SCSV], [])
    | (`TLS_1_3, _) -> ([], [])
    | _ -> ([], [`SecureRenegotiation (Cstruct.create 0)])
  in

  let client_hello =
    { dch with
        ciphersuites = dch.ciphersuites @ ciphers ;
        extensions   = dch.extensions @ extensions }
  in

  let client_hello, ch, raw =
    match config.Config.cached_ticket, config.Config.ticket_cache with
    | None, _ | _, None ->
      let ch = ClientHello client_hello in
      client_hello, ch, Writer.assemble_handshake ch
    | Some (psk, epoch), Some cache ->
      let kex = `PskKeyExchangeModes [ Packet.PSK_KE_DHE ] in
      (* what next!? *)
      let now = cache.Config.timestamp () in
      (* TODO check lifetime! *)
      let obf_age =
        let span = Ptime.Span.to_float_s (Ptime.diff now psk.issued_at) in
        (* _in milliseconds_ *)
        let ms = int_of_float (span *. 1000.) in
        Int32.add psk.obfuscation (Int32.of_int ms)
      in
      let cipher = match Ciphersuite.ciphersuite_to_ciphersuite13 epoch.ciphersuite with
        | None -> assert false
        | Some c -> c
      in
      (* if all goes well, we can compute the binder key and embed into ch! *)
      let early_secret = Handshake_crypto13.(derive (empty cipher) psk.secret) in
      let binder_key = Handshake_crypto13.derive_secret early_secret "res binder" Cstruct.empty in

      let hash = Cstruct.create (Mirage_crypto.Hash.digest_size (Ciphersuite.hash13 cipher)) in
      let incomplete_psks = [ (psk.identifier, obf_age), hash ] in
      let ch' = { client_hello with extensions = client_hello.extensions @ [ kex ; `PreSharedKeys incomplete_psks ] } in
      let ch'_raw = Writer.assemble_handshake (ClientHello ch') in

      let binders_len = binders_len incomplete_psks in
      let ch_part = Cstruct.(sub ch'_raw 0 (length ch'_raw - binders_len)) in
      let binder = Handshake_crypto13.finished early_secret.hash binder_key ch_part in
      let blen = Cstruct.length binder in
      let prefix = Cstruct.create 3 in
      Cstruct.BE.set_uint16 prefix 0 (blen + 1) ;
      Cstruct.set_uint8 prefix 2 blen ;
      let raw = Cstruct.concat [ ch_part ; prefix ; binder ] in

      let psks = [(psk.identifier, obf_age), binder] in
      let client_hello' = { client_hello with extensions = client_hello.extensions @ [ kex ; `PreSharedKeys psks ] } in
      let ch' = ClientHello client_hello' in
      client_hello', ch', raw
  in

  let machina = AwaitServerHello (client_hello, secrets, [raw]) in

    (* from RFC5246, appendix E.1
   TLS clients that wish to negotiate with older servers MAY send any
   value {03,XX} as the record layer version number.  Typical values
   would be {03,00}, the lowest version number supported by the client,
   and the value of ClientHello.client_version.  No single value will
   guarantee interoperability with all old servers, but this is a
   complex topic beyond the scope of this document. *)
  let version = min_protocol_version Config.(config.protocol_versions) in
  let handshake = {
    state.handshake with
      machina          = Client machina ;
      protocol_version = version
  } in
  let state = { state with handshake } in

  Tracing.hs ~tag:"handshake-out" ch ;
  send_records state [(Packet.HANDSHAKE, raw)]

let server config = new_state Config.(of_server config) `Server

let epoch state =
  Option.to_result ~none:() (epoch_of_hs state.handshake)

let export_key_material (e : epoch_data) ?context label length =
  match e.protocol_version with
  | `TLS_1_3 ->
    let hash =
      let cipher = Option.get (Ciphersuite.ciphersuite_to_ciphersuite13 e.ciphersuite) in
      Ciphersuite.hash13 cipher
    in
    let ems = e.exporter_master_secret in
    let prk =
      let ctx = Mirage_crypto.Hash.digest hash Cstruct.empty in
      Handshake_crypto13.derive_secret_no_hash hash ems ~ctx label
    in
    let ctx = Option.(value ~default:Cstruct.empty (map Cstruct.of_string context)) in
    Handshake_crypto13.derive_secret_no_hash
      hash prk ~ctx:(Mirage_crypto.Hash.digest hash ctx)
      ~length "exporter"
  | #tls_before_13 as v ->
    let seed =
      let base =
        match e.side with
        | `Server -> Cstruct.append e.peer_random e.own_random
        | `Client -> Cstruct.append e.own_random e.peer_random
      in
      match context with
      | None -> base
      | Some data ->
        let len = Cstruct.create 2 in
        Cstruct.BE.set_uint16 len 0 (String.length data);
        Cstruct.concat [ base ; len ; Cstruct.of_string data ]
    in
    Handshake_crypto.pseudo_random_function v e.ciphersuite
      length e.master_secret label seed
