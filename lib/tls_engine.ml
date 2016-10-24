open Nocrypto

open Tls_utils
open Tls_core
open Tls_state


type state = Tls_state.state

type error = Tls_state.error
type fatal = Tls_state.fatal
type failure = Tls_state.failure [@@deriving sexp]

let alert_of_authentication_failure = function
  | `Leaf (`LeafCertificateExpired _) -> Tls_packet.CERTIFICATE_EXPIRED
  | _ -> Tls_packet.BAD_CERTIFICATE

let alert_of_error = function
  | `NoConfiguredVersion _ -> Tls_packet.PROTOCOL_VERSION
  | `NoConfiguredCiphersuite _ -> Tls_packet.HANDSHAKE_FAILURE
  | `NoConfiguredHash _ -> Tls_packet.HANDSHAKE_FAILURE
  | `AuthenticationFailure err -> alert_of_authentication_failure err
  | `NoMatchingCertificateFound _ -> Tls_packet.UNRECOGNIZED_NAME
  | `NoCertificateConfigured -> Tls_packet.HANDSHAKE_FAILURE
  | `CouldntSelectCertificate -> Tls_packet.HANDSHAKE_FAILURE

let alert_of_fatal = function
  | `NoSecureRenegotiation -> Tls_packet.HANDSHAKE_FAILURE
  | `MACUnderflow -> Tls_packet.BAD_RECORD_MAC
  | `MACMismatch -> Tls_packet.BAD_RECORD_MAC
  | `RecordOverflow _ -> Tls_packet.RECORD_OVERFLOW
  | `UnknownRecordVersion _ -> Tls_packet.PROTOCOL_VERSION
  | `UnknownContentType _ -> Tls_packet.UNEXPECTED_MESSAGE
  | `ReaderError _ -> Tls_packet.ILLEGAL_PARAMETER
  | `CannotHandleApplicationDataYet -> Tls_packet.UNEXPECTED_MESSAGE
  | `NoHeartbeat -> Tls_packet.UNEXPECTED_MESSAGE
  | `BadRecordVersion _ -> Tls_packet.PROTOCOL_VERSION
  | `InvalidRenegotiation -> Tls_packet.HANDSHAKE_FAILURE
  | `InvalidServerHello -> Tls_packet.UNSUPPORTED_EXTENSION
  | `InvalidRenegotiationVersion _ -> Tls_packet.HANDSHAKE_FAILURE
  | `NoCertificateReceived -> Tls_packet.HANDSHAKE_FAILURE
  | `NotRSACertificate -> Tls_packet.BAD_CERTIFICATE
  | `InvalidCertificateUsage -> Tls_packet.BAD_CERTIFICATE
  | `InvalidCertificateExtendedUsage -> Tls_packet.BAD_CERTIFICATE
  | `NoVersion _ -> Tls_packet.PROTOCOL_VERSION
  | `InvalidDH -> Tls_packet.INSUFFICIENT_SECURITY
  | `BadFinished -> Tls_packet.HANDSHAKE_FAILURE
  | `HandshakeFragmentsNotEmpty -> Tls_packet.HANDSHAKE_FAILURE
  | `InvalidSession -> Tls_packet.HANDSHAKE_FAILURE
  | `UnexpectedCCS -> Tls_packet.UNEXPECTED_MESSAGE
  | `UnexpectedHandshake _ -> Tls_packet.UNEXPECTED_MESSAGE
  | `RSASignatureMismatch -> Tls_packet.HANDSHAKE_FAILURE
  | `HashAlgorithmMismatch -> Tls_packet.HANDSHAKE_FAILURE
  | `NotRSASignature -> Tls_packet.HANDSHAKE_FAILURE
  | `RSASignatureVerificationFailed -> Tls_packet.HANDSHAKE_FAILURE
  | `KeyTooSmall -> Tls_packet.INSUFFICIENT_SECURITY
  | `BadCertificateChain -> Tls_packet.BAD_CERTIFICATE
  | `NoCiphersuite _ -> Tls_packet.HANDSHAKE_FAILURE
  | `InvalidClientHello -> Tls_packet.HANDSHAKE_FAILURE
  | `InappropriateFallback -> Tls_packet.INAPPROPRIATE_FALLBACK

let alert_of_failure = function
  | `Error x -> alert_of_error x
  | `Fatal x -> alert_of_fatal x

let string_of_failure = function
  | `Error (`AuthenticationFailure v) -> "authentication failure: " ^ X509.Validation.validation_error_to_string v
  | f -> Sexplib.Sexp.to_string_hum (sexp_of_failure f)

type ret = [

  | `Ok of [ `Ok of state | `Eof | `Alert of Tls_packet.alert_type ]
         * [ `Response of Cstruct.t option ]
         * [ `Data of Cstruct.t option ]

  | `Fail of failure * [ `Response of Cstruct.t ]
]


let (<+>) = Cs.(<+>)

let new_state config role =
  let handshake_state = match role with
    | `Client -> Client ClientInitial
    | `Server -> Server AwaitClientHello
  in
  let version = max_protocol_version Tls_config.(config.protocol_versions) in
  let handshake = {
    session          = [] ;
    protocol_version = version ;
    machina          = handshake_state ;
    config           = config ;
    hs_fragment      = Cstruct.create 0 ;
  }
  in
  {
    handshake = handshake ;
    decryptor = None ;
    encryptor = None ;
    fragment  = Cstruct.create 0 ;
  }

type raw_record = tls_hdr * Cstruct.t [@@deriving sexp]

(* well-behaved pure encryptor *)
let encrypt (version : tls_version) (st : crypto_state) ty buf =
  match st with
  | None     -> (st, buf)
  | Some ctx ->
      let pseudo_hdr =
        let seq = ctx.sequence
        and ver = pair_of_tls_version version
        in
        Tls_crypto.pseudo_header seq ty ver (Cstruct.len buf)
      in
      let to_encrypt mac mac_k =
        let signature = Tls_crypto.mac mac mac_k pseudo_hdr buf in
        buf <+> signature
      in
      let c_st, enc =
        match ctx.cipher_st with
        | Stream s ->
           let to_encrypt = to_encrypt s.hmac s.hmac_secret in
           let (message, key') =
             Tls_crypto.encrypt_stream ~cipher:s.cipher ~key:s.cipher_secret to_encrypt in
           (Stream { s with cipher_secret = key'}, message)

        | CBC c ->
           let enc iv =
             let to_encrypt = to_encrypt c.hmac c.hmac_secret in
             Tls_crypto.encrypt_cbc ~cipher:c.cipher ~key:c.cipher_secret ~iv to_encrypt
           in
           ( match c.iv_mode with
             | Random_iv ->
                let iv = Rng.generate (Tls_crypto.cbc_block c.cipher) in
                let m, _ = enc iv in
                (CBC c, iv <+> m)
             | Iv iv ->
                let m, iv' = enc iv in
                (CBC { c with iv_mode = Iv iv' }, m) )

        | AEAD c ->
           let explicit_nonce = Tls_crypto.sequence_buf ctx.sequence in
           let nonce = c.nonce <+> explicit_nonce
           in
           let msg =
             Tls_crypto.encrypt_aead ~cipher:c.cipher ~key:c.cipher_secret ~nonce ~adata:pseudo_hdr buf
           in
           (AEAD c, explicit_nonce <+> msg)
      in
      (Some { sequence = Int64.succ ctx.sequence ; cipher_st = c_st }, enc)

(* well-behaved pure decryptor *)
let verify_mac sequence mac mac_k ty ver decrypted =
  let macstart = Cstruct.len decrypted - Hash.digest_size mac in
  guard (macstart >= 0) (`Fatal `MACUnderflow) >>= fun () ->
  let (body, mmac) = Cstruct.split decrypted macstart in
  let cmac =
    let ver = pair_of_tls_version ver in
    let hdr = Tls_crypto.pseudo_header sequence ty ver (Cstruct.len body) in
    Tls_crypto.mac mac mac_k hdr body in
  guard (Cs.equal cmac mmac) (`Fatal `MACMismatch) >|= fun () ->
  body


let decrypt (version : tls_version) (st : crypto_state) ty buf =

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
    compute_mac seq mac mac_k buf >>= fun _ -> fail (`Fatal `MACMismatch)
  in

  let dec ctx =
    let seq = ctx.sequence in
    match ctx.cipher_st with
    | Stream s ->
        let (message, key') = Tls_crypto.decrypt_stream ~cipher:s.cipher ~key:s.cipher_secret buf in
        compute_mac seq s.hmac s.hmac_secret message >|= fun msg ->
        (Stream { s with cipher_secret = key' }, msg)

    | CBC c ->
       let dec iv buf =
         match Tls_crypto.decrypt_cbc ~cipher:c.cipher ~key:c.cipher_secret ~iv buf with
         | None ->
            mask_decrypt_failure seq c.hmac c.hmac_secret
         | Some (dec, iv') ->
            compute_mac seq c.hmac c.hmac_secret dec >|= fun msg ->
            (msg, iv')
       in
       ( match c.iv_mode with
         | Iv iv ->
            dec iv buf >|= fun (msg, iv') ->
            CBC { c with iv_mode = Iv iv' }, msg
         | Random_iv ->
            if Cstruct.len buf < Tls_crypto.cbc_block c.cipher then
              fail (`Fatal `MACUnderflow)
            else
              let iv, buf = Cstruct.split buf (Tls_crypto.cbc_block c.cipher) in
              dec iv buf >|= fun (msg, _) ->
              (CBC c, msg) )

    | AEAD c ->
       if Cstruct.len buf < 8 then
         fail (`Fatal `MACUnderflow)
       else
         let explicit_nonce, buf = Cstruct.split buf 8 in
         let adata =
           let ver = pair_of_tls_version version in
           Tls_crypto.pseudo_header seq ty ver (Cstruct.len buf - 16)
         and nonce = c.nonce <+> explicit_nonce
         in
         match Tls_crypto.decrypt_aead ~cipher:c.cipher ~key:c.cipher_secret ~nonce ~adata buf with
         | None -> fail (`Fatal `MACMismatch)
         | Some x -> return (AEAD c, x)
  in
  match st with
  | None     -> return (st, buf)
  | Some ctx ->
      dec ctx >>= fun (st', msg) ->
      let ctx' = {
        sequence  = Int64.succ ctx.sequence ;
        cipher_st = st'
      }
      in
      return (Some ctx', msg)

(* party time *)
let rec separate_records : Cstruct.t ->  ((tls_hdr * Cstruct.t) list * Cstruct.t) eff
= fun buf ->
  let open Tls_reader in
  match parse_record buf with
  | Ok (`Fragment b) -> return ([], b)
  | Ok (`Record (packet, fragment)) ->
    separate_records fragment >|= fun (tl, frag) ->
    (packet :: tl, frag)
  | Error (Overflow x) ->
    Tls_tracing.cs ~tag:"buf-in" buf ;
    fail (`Fatal (`RecordOverflow x))
  | Error (UnknownVersion v) ->
    Tls_tracing.cs ~tag:"buf-in" buf ;
    fail (`Fatal (`UnknownRecordVersion v))
  | Error (UnknownContent c) ->
    Tls_tracing.cs ~tag:"buf-in" buf ;
    fail (`Fatal (`UnknownContentType c))
  | Error e ->
    Tls_tracing.cs ~tag:"buf-in" buf ;
    fail (`Fatal (`ReaderError e))


let encrypt_records encryptor version records =
  let rec split = function
    | [] -> []
    | (t1, a) :: xs when Cstruct.len a >= 1 lsl 14 ->
      let fst, snd = Cstruct.split a (1 lsl 14) in
      (t1, fst) :: split ((t1, snd) :: xs)
    | x::xs -> x :: split xs

  and crypt st = function
    | []            -> (st, [])
    | (ty, buf)::rs ->
        let (st, enc)  = encrypt version st ty buf in
        let (st, encs) = crypt st rs in
        (st, (ty, enc) :: encs)
  in
  crypt encryptor (split records)

module Alert = struct

  open Tls_packet

  let make ?level typ = (ALERT, Tls_writer.assemble_alert ?level typ)

  let close_notify = make ~level:WARNING CLOSE_NOTIFY

  let handle buf =
    match Tls_reader.parse_alert buf with
    | Ok (_, a_type as alert) ->
        Tls_tracing.sexpf ~tag:"alert-in" ~f:sexp_of_tls_alert alert ;
        let err = match a_type with
          | CLOSE_NOTIFY -> `Eof
          | _            -> `Alert a_type in
        return (err, [`Record close_notify])
    | Error re -> fail (`Fatal (`ReaderError re))
end

let hs_can_handle_appdata s =
  (* When is a TLS session up for some application data?
     - initial handshake must be finished!
     - renegotiation must not be in progress
     --> thus only ok for Established
     - but ok if server sent a HelloRequest and can get first some appdata then ClientHello
     --> or converse: client sent ClientHello, waiting for ServerHello *)
  match s.machina with
  | Server Established | Server AwaitClientHelloRenegotiate
  | Client Established | Client AwaitServerHelloRenegotiate _ -> true
  | _ -> false

let rec separate_handshakes buf =
  match Tls_reader.parse_handshake_frame buf with
  | None, rest   -> return ([], rest)
  | Some hs, rest ->
    separate_handshakes rest >|= fun (rt, frag) ->
    (hs :: rt, frag)

let handle_change_cipher_spec = function
  | Client cs -> Tls_handshake_client.handle_change_cipher_spec cs
  | Server ss -> Tls_handshake_server.handle_change_cipher_spec ss

and handle_handshake = function
  | Client cs -> Tls_handshake_client.handle_handshake cs
  | Server ss -> Tls_handshake_server.handle_handshake ss

let non_empty cs =
  if Cstruct.len cs = 0 then None else Some cs

let handle_packet hs buf = function
(* RFC 5246 -- 6.2.1.:
   Implementations MUST NOT send zero-length fragments of Handshake,
   Alert, or ChangeCipherSpec content types.  Zero-length fragments of
   Application data MAY be sent as they are potentially useful as a
   traffic analysis countermeasure.
 *)

  | Tls_packet.ALERT ->
      Alert.handle buf >|= fun (err, out) ->
        (hs, out, None, err)

  | Tls_packet.APPLICATION_DATA ->
    if hs_can_handle_appdata hs then
      (Tls_tracing.cs ~tag:"application-data-in" buf;
       return (hs, [], non_empty buf, `No_err))
    else
      fail (`Fatal `CannotHandleApplicationDataYet)

  | Tls_packet.CHANGE_CIPHER_SPEC ->
      handle_change_cipher_spec hs.machina hs buf
      >|= fun (hs, items) -> (hs, items, None, `No_err)

  | Tls_packet.HANDSHAKE ->
     separate_handshakes (hs.hs_fragment <+> buf)
     >>= fun (hss, hs_fragment) ->
       foldM (fun (hs, items) raw ->
         handle_handshake hs.machina hs raw
         >|= fun (hs', items') -> (hs', items @ items'))
       (hs, []) hss
     >|= fun (hs, items) ->
       ({ hs with hs_fragment }, items, None, `No_err)

  | Tls_packet.HEARTBEAT -> fail (`Fatal `NoHeartbeat)


(* the main thingy *)
let handle_raw_record state (hdr, buf as record : raw_record) =

  Tls_tracing.sexpf ~tag:"record-in" ~f:sexp_of_raw_record record ;

  let hs = state.handshake in
  let version = hs.protocol_version in
  ( match hs.machina, version_eq hdr.version version with
    | Client (AwaitServerHello _), _     -> return ()
    | Server (AwaitClientHello)  , _     -> return ()
    | _                          , true  -> return ()
    | _                          , false -> fail (`Fatal (`BadRecordVersion hdr.version)) )
  >>= fun () ->
  decrypt version state.decryptor hdr.content_type buf
  >>= fun (dec_st, dec) ->
  handle_packet state.handshake dec hdr.content_type
  >|= fun (handshake, items, data, err) ->
  let (encryptor, decryptor, encs) =
    List.fold_left (fun (enc, dec, es) -> function
      | `Change_enc enc' -> (enc', dec, es)
      | `Change_dec dec' -> (enc, dec', es)
      | `Record r       ->
          let (enc', encbuf) = encrypt_records enc handshake.protocol_version [r] in
          (enc', dec, es @ encbuf))
    (state.encryptor, dec_st, [])
    items
  in
  let state' = { state with handshake ; encryptor ; decryptor } in

  Tls_tracing.sexpfs ~tag:"record-out" ~f:sexp_of_record encs ;

  (state', encs, data, err)

let maybe_app a b = match a, b with
  | Some x, Some y -> Some (x <+> y)
  | Some x, None   -> Some x
  | None  , Some y -> Some y
  | None  , None   -> None

let assemble_records (version : tls_version) : record list -> Cstruct.t =
  o Cs.appends @@ List.map @@ Tls_writer.assemble_hdr version

(* main entry point *)
let handle_tls state buf =

  (* Tls_tracing.sexpf ~tag:"state-in" ~f:sexp_of_state state ; *)

  let rec handle_records st = function
    | []    -> return (st, [], None, `No_err)
    | r::rs ->
        handle_raw_record st r >>= function
          | (st, raw_rs, data, `No_err) ->
              handle_records st rs >|= fun (st', raw_rs', data', err') ->
                (st', raw_rs @ raw_rs', maybe_app data data', err')
          | res -> return res
  in
  match
    separate_records (state.fragment <+> buf)
    >>= fun (in_records, fragment) ->
      handle_records state in_records
    >|= fun (state', out_records, data, err) ->
      let version = state'.handshake.protocol_version in
      let resp    = match out_records with
                    | [] -> None
                    | _  -> Some (assemble_records version out_records) in
      ({ state' with fragment }, resp, data, err)
  with
  | Ok (state, resp, data, err) ->
      let res = match err with
        | `Eof ->
          Tls_tracing.sexpf ~tag:"eof-out" ~f:Sexplib.Conv.sexp_of_unit () ;
          `Eof
        | `Alert al ->
          Tls_tracing.sexpf ~tag:"ok-alert-out" ~f:Tls_packet.sexp_of_alert_type al ;
          `Alert al
        | `No_err ->
          Tls_tracing.sexpf ~tag:"state-out" ~f:sexp_of_state state ;
          `Ok state
      in
      `Ok (res, `Response resp, `Data data)
  | Error x ->
      let version = state.handshake.protocol_version in
      let alert   = alert_of_failure x in
      let record  = Alert.make alert in
      let _, enc  = encrypt_records state.encryptor version [record] in
      let resp    = assemble_records version enc in
      Tls_tracing.sexpf ~tag:"fail-alert-out" ~f:sexp_of_tls_alert (Tls_packet.FATAL, alert) ;
      Tls_tracing.sexpf ~tag:"failure" ~f:sexp_of_failure x ;
      `Fail (x, `Response resp)

let send_records (st : state) records =
  let version = st.handshake.protocol_version in
  let (encryptor, encs) =
    encrypt_records st.encryptor version records in
  let data = assemble_records version encs in
  ({ st with encryptor }, data)

(* utility for user *)
let can_handle_appdata s = hs_can_handle_appdata s.handshake

(* another entry for user data *)
let send_application_data st css =
  match can_handle_appdata st with
  | true ->
     Tls_tracing.css ~tag:"application-data-out" css ;
     let datas = match st.encryptor with
       (* Mitigate implicit IV in CBC mode: prepend empty fragment *)
       | Some { cipher_st = CBC { iv_mode = Iv _ } } -> Cstruct.create 0 :: css
       | _                                           -> css
     in
     let ty = Tls_packet.APPLICATION_DATA in
     let data = List.map (fun cs -> (ty, cs)) datas in
     Some (send_records st data)
  | false -> None

let send_close_notify st = send_records st [Alert.close_notify]

let reneg st =
  let hs = st.handshake in
  match hs.machina with
  | Server Established ->
     ( match Tls_handshake_server.hello_request hs with
       | Ok (handshake, [`Record hr]) -> Some (send_records { st with handshake } [hr])
       | _                            -> None )
  | Client Established ->
     ( match Tls_handshake_client.answer_hello_request hs with
       | Ok (handshake, [`Record ch]) -> Some (send_records { st with handshake } [ch])
       | _                            -> None )
  | _                        -> None

let client config =
  let config = Tls_config.of_client config in
  let state = new_state config `Client in
  let dch, version = Tls_handshake_client.default_client_hello config in
  let ciphers, extensions = match version with
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
    | TLS_1_0 -> ([Tls_packet.TLS_EMPTY_RENEGOTIATION_INFO_SCSV], [])
    | TLS_1_1 | TLS_1_2 -> ([], [`SecureRenegotiation (Cstruct.create 0)])
  in

  let client_hello =
    { dch with
        ciphersuites = dch.ciphersuites @ ciphers ;
        extensions   = dch.extensions @ extensions }
  in

  let ch = ClientHello client_hello in
  let raw = Tls_writer.assemble_handshake ch in
  let machina = AwaitServerHello (client_hello, [raw]) in

    (* from RFC5246, appendix E.1
   TLS clients that wish to negotiate with older servers MAY send any
   value {03,XX} as the record layer version number.  Typical values
   would be {03,00}, the lowest version number supported by the client,
   and the value of ClientHello.client_version.  No single value will
   guarantee interoperability with all old servers, but this is a
   complex topic beyond the scope of this document. *)
  let version = min_protocol_version Tls_config.(config.protocol_versions) in
  let handshake = {
    state.handshake with
      machina          = Client machina ;
      protocol_version = version
  } in
  let state = { state with handshake } in

  (* Tls_tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake ch ; *)
  Tls_tracing.sexpf ~tag:"state-out" ~f:sexp_of_state state ;
  send_records state [(Tls_packet.HANDSHAKE, raw)]

let server config = new_state Tls_config.(of_server config) `Server

open Sexplib
open Sexplib.Conv

type epoch = [
  | `InitialEpoch
  | `Epoch of epoch_data
] [@@deriving sexp]

let epoch state =
  let hs = state.handshake in
  match hs.session with
  | []           -> `InitialEpoch
  | session :: _ ->
     let own_random , peer_random =
       match hs.machina with
       | Client _ -> session.client_random , session.server_random
       | Server _ -> session.server_random , session.client_random
     in
     `Epoch {
        protocol_version       = hs.protocol_version ;
        ciphersuite            = session.ciphersuite ;
        peer_random ;
        peer_certificate       = session.peer_certificate ;
        peer_certificate_chain = session.peer_certificate_chain ;
        peer_name              = Tls_config.(hs.config.peer_name) ;
        trust_anchor           = session.trust_anchor ;
        own_random ;
        own_certificate        = session.own_certificate ;
        own_private_key        = session.own_private_key ;
        own_name               = session.own_name ;
        received_certificates  = session.received_certificates ;
        master_secret          = session.master_secret ;
        session_id             = session.session_id ;
        extended_ms            = session.extended_ms ;
      }
