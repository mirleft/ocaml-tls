open Nocrypto

open Utils
open Core
open State


type state = State.state

type error = State.error
type fatal = State.fatal
type failure = State.failure with sexp

let alert_of_authentication_failure = function
  | X509.Certificate.SelfSigned _ -> Packet.UNKNOWN_CA
  | X509.Certificate.NoTrustAnchor -> Packet.UNKNOWN_CA
  | X509.Certificate.CertificateExpired _ -> Packet.CERTIFICATE_EXPIRED
  | _ -> Packet.BAD_CERTIFICATE

let alert_of_error = function
  | `NoConfiguredVersion _ -> Packet.PROTOCOL_VERSION
  | `NoConfiguredCiphersuite _ -> Packet.HANDSHAKE_FAILURE
  | `NoSecureRenegotiation -> Packet.HANDSHAKE_FAILURE
  | `NoConfiguredHash _ -> Packet.HANDSHAKE_FAILURE
  | `AuthenticationFailure err -> alert_of_authentication_failure err
  | `NoMatchingCertificateFound _ -> Packet.HANDSHAKE_FAILURE
  | `NoCertificateConfigured -> Packet.HANDSHAKE_FAILURE
  | `CouldntSelectCertificate -> Packet.HANDSHAKE_FAILURE

let alert_of_fatal = function
  | `MACUnderflow -> Packet.BAD_RECORD_MAC
  | `MACMismatch -> Packet.BAD_RECORD_MAC
  | `RecordOverflow _ -> Packet.RECORD_OVERFLOW
  | `UnknownRecordVersion _ -> Packet.PROTOCOL_VERSION
  | `UnknownContentType _ -> Packet.UNEXPECTED_MESSAGE
  | `ReaderError _ -> Packet.UNEXPECTED_MESSAGE
  | `CannotHandleApplicationDataYet -> Packet.UNEXPECTED_MESSAGE
  | `NoHeartbeat -> Packet.UNEXPECTED_MESSAGE
  | `BadRecordVersion _ -> Packet.PROTOCOL_VERSION
  | `InvalidRenegotiation -> Packet.HANDSHAKE_FAILURE
  | `InvalidServerHello -> Packet.HANDSHAKE_FAILURE
  | `InvalidRenegotiationVersion _ -> Packet.HANDSHAKE_FAILURE
  | `NoCertificateReceived -> Packet.HANDSHAKE_FAILURE
  | `NotRSACertificate -> Packet.BAD_CERTIFICATE
  | `InvalidCertificateUsage -> Packet.BAD_CERTIFICATE
  | `InvalidCertificateExtendedUsage -> Packet.BAD_CERTIFICATE
  | `NoVersion _ -> Packet.PROTOCOL_VERSION
  | `InvalidDH -> Packet.INSUFFICIENT_SECURITY
  | `BadFinished -> Packet.HANDSHAKE_FAILURE
  | `HandshakeFragmentsNotEmpty -> Packet.HANDSHAKE_FAILURE
  | `InvalidSession -> Packet.HANDSHAKE_FAILURE
  | `UnexpectedCCS -> Packet.UNEXPECTED_MESSAGE
  | `UnexpectedHandshake _ -> Packet.UNEXPECTED_MESSAGE
  | `RSASignatureMismatch -> Packet.HANDSHAKE_FAILURE
  | `HashAlgorithmMismatch -> Packet.HANDSHAKE_FAILURE
  | `NotRSASignature -> Packet.HANDSHAKE_FAILURE
  | `RSASignatureVerificationFailed -> Packet.HANDSHAKE_FAILURE
  | `KeyTooSmall -> Packet.INSUFFICIENT_SECURITY
  | `BadCertificateChain -> Packet.BAD_CERTIFICATE
  | `MixedCiphersuites -> Packet.HANDSHAKE_FAILURE
  | `NoCiphersuite _ -> Packet.HANDSHAKE_FAILURE
  | `InvalidClientHello -> Packet.HANDSHAKE_FAILURE
  | `InappropriateFallback -> Packet.INAPPROPRIATE_FALLBACK

let alert_of_failure = function
  | `Error x -> alert_of_error x
  | `Fatal x -> alert_of_fatal x

let string_of_failure f =
  Sexplib.Sexp.to_string_hum (sexp_of_failure f)

type ret = [

  | `Ok of [ `Ok of state | `Eof | `Alert of Packet.alert_type ]
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
  let version = max_protocol_version Config.(config.protocol_versions) in
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

type raw_record = tls_hdr * Cstruct_s.t with sexp

(* well-behaved pure encryptor *)
let encrypt (version : tls_version) (st : crypto_state) ty buf =
  match st with
  | None     -> (st, buf)
  | Some ctx ->
      let pseudo_hdr =
        let seq = ctx.sequence
        and ver = pair_of_tls_version version
        in
        Crypto.pseudo_header seq ty ver (Cstruct.len buf)
      in
      let to_encrypt mac mac_k =
        let signature = Crypto.mac mac mac_k pseudo_hdr buf in
        buf <+> signature
      in
      let c_st, enc =
        match ctx.cipher_st with
        | Stream s ->
           let to_encrypt = to_encrypt s.hmac s.hmac_secret in
           let (message, key') =
             Crypto.encrypt_stream ~cipher:s.cipher ~key:s.cipher_secret to_encrypt in
           (Stream { s with cipher_secret = key'}, message)

        | CBC c ->
           let enc iv =
             let to_encrypt = to_encrypt c.hmac c.hmac_secret in
             Crypto.encrypt_cbc ~cipher:c.cipher ~key:c.cipher_secret ~iv to_encrypt
           in
           ( match c.iv_mode with
             | Random_iv ->
                let iv = Rng.generate (Crypto.cbc_block c.cipher) in
                let m, _ = enc iv in
                (CBC c, iv <+> m)
             | Iv iv ->
                let m, iv' = enc iv in
                (CBC { c with iv_mode = Iv iv' }, m) )

        | CCM c ->
           let explicit_nonce = Crypto.sequence_buf ctx.sequence in
           let nonce = c.nonce <+> explicit_nonce
           in
           let msg =
             Crypto.encrypt_ccm ~cipher:c.cipher ~key:c.cipher_secret ~nonce ~adata:pseudo_hdr buf
           in
           (CCM c, explicit_nonce <+> msg)
      in
      (Some { sequence = Int64.succ ctx.sequence ; cipher_st = c_st }, enc)

(* well-behaved pure decryptor *)
let verify_mac sequence mac mac_k ty ver decrypted =
  let macstart = Cstruct.len decrypted - Hash.digest_size mac in
  guard (macstart >= 0) (`Fatal `MACUnderflow) >>= fun () ->
  let (body, mmac) = Cstruct.split decrypted macstart in
  let cmac =
    let ver = pair_of_tls_version ver in
    let hdr = Crypto.pseudo_header sequence ty ver (Cstruct.len body) in
    Crypto.mac mac mac_k hdr body in
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
        let (message, key') = Crypto.decrypt_stream ~cipher:s.cipher ~key:s.cipher_secret buf in
        compute_mac seq s.hmac s.hmac_secret message >|= fun msg ->
        (Stream { s with cipher_secret = key' }, msg)

    | CBC c ->
       let dec iv buf =
         match Crypto.decrypt_cbc ~cipher:c.cipher ~key:c.cipher_secret ~iv buf with
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
            if Cstruct.len buf < Crypto.cbc_block c.cipher then
              fail (`Fatal `MACUnderflow)
            else
              let iv, buf = Cstruct.split buf (Crypto.cbc_block c.cipher) in
              dec iv buf >|= fun (msg, _) ->
              (CBC c, msg) )

    | CCM c ->
       if Cstruct.len buf < 8 then
         fail (`Fatal `MACUnderflow)
       else
         let explicit_nonce, buf = Cstruct.split buf 8 in
         let adata =
           let ver = pair_of_tls_version version in
           Crypto.pseudo_header seq ty ver (Cstruct.len buf - 16)
         and nonce = c.nonce <+> explicit_nonce
         in
         match Crypto.decrypt_ccm ~cipher:c.cipher ~key:c.cipher_secret ~nonce ~adata buf with
         | None -> fail (`Fatal `MACMismatch)
         | Some x -> return (CCM c, x)
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
let rec separate_records : Cstruct.t ->  ((tls_hdr * Cstruct.t) list * Cstruct.t) or_error
= fun buf ->
  let open Cstruct in
  if len buf <= 5 then
    return ([], buf)
  else
    let open Reader in
    let payload = shift buf 5 in
    match parse_hdr buf with
    | (Some _, Some _, size) when size > (1 lsl 14 + 2048) ->
       (* 2 ^ 14 + 2048 for TLSCiphertext
          2 ^ 14 + 1024 for TLSCompressed
          2 ^ 14 for TLSPlaintext *)
       Tracing.cs ~tag:"buf-in" buf ;
       fail (`Fatal (`RecordOverflow size))
    | (Some _, Some _, size) when size > len payload       ->
       return ([], buf)
    | (Some content_type, Some version, size)              ->
       separate_records (shift payload size) >|= fun (tl, frag) ->
       let packet = ({ content_type ; version }, sub payload 0 size) in
       (packet :: tl, frag)
    | (_, None, _)                                         ->
       Tracing.cs ~tag:"buf-in" buf ;
       fail (`Fatal (`UnknownRecordVersion (Reader.parse_version_int (shift buf 1))))
    | (None, _, _)                                         ->
       Tracing.cs ~tag:"buf-in" buf ;
       fail (`Fatal (`UnknownContentType (get_uint8 buf 0)))


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

  open Packet

  let make typ = (ALERT, Writer.assemble_alert typ)

  let close_notify = make CLOSE_NOTIFY

  let handle buf =
    match Reader.parse_alert buf with
    | Reader.Or_error.Ok (_, a_type as alert) ->
        Tracing.sexpf ~tag:"alert-in" ~f:sexp_of_tls_alert alert ;
        let err = match a_type with
          | CLOSE_NOTIFY -> `Eof
          | _            -> `Alert a_type in
        return (err, [`Record close_notify])
    | Reader.Or_error.Error re -> fail (`Fatal (`ReaderError re))
end

let hs_can_handle_appdata s =
  match s.session with
  | [] -> false
  | _  ->
    (* if there is a renegotiation going on -
       specifically ChangeCipherSuite was transmitted, waiting for Finished -
       we should not allow any application data (since the
       new crypto context, not authenticated by Finished, is in use *)
    match s.machina with
    | Server (AwaitClientFinished _)
    | Client (AwaitServerFinished _) -> false
    | _ -> true

let rec separate_handshakes buf =
  if Cstruct.len buf < 4 then
    return ([], buf)
  else
    match Reader.parse_handshake_length buf with
    | size when (size + 4) > Cstruct.len buf -> return ([], buf)
    | size ->
       let hs, rest = Cstruct.split buf (size + 4) in
       separate_handshakes rest >|= fun (rt, frag) ->
       (hs :: rt, frag)

let handle_change_cipher_spec = function
  | Client cs -> Handshake_client.handle_change_cipher_spec cs
  | Server ss -> Handshake_server.handle_change_cipher_spec ss

and handle_handshake = function
  | Client cs -> Handshake_client.handle_handshake cs
  | Server ss -> Handshake_server.handle_handshake ss

let non_empty cs =
  if Cstruct.len cs = 0 then None else Some cs

let handle_packet hs buf = function
(* RFC 5246 -- 6.2.1.:
   Implementations MUST NOT send zero-length fragments of Handshake,
   Alert, or ChangeCipherSpec content types.  Zero-length fragments of
   Application data MAY be sent as they are potentially useful as a
   traffic analysis countermeasure.
 *)

  | Packet.ALERT ->
      Alert.handle buf >|= fun (err, out) ->
        (hs, out, None, `Pass, err)

  | Packet.APPLICATION_DATA ->
    if hs_can_handle_appdata hs then
      (Tracing.cs ~tag:"application-data-in" buf;
       return (hs, [], non_empty buf, `Pass, `No_err))
    else
      fail (`Fatal `CannotHandleApplicationDataYet)

  | Packet.CHANGE_CIPHER_SPEC ->
      handle_change_cipher_spec hs.machina hs buf
      >|= fun (hs, items, dec_cmd) -> (hs, items, None, dec_cmd, `No_err)

  | Packet.HANDSHAKE ->
     separate_handshakes (hs.hs_fragment <+> buf)
     >>= fun (hss, hs_fragment) ->
       foldM (fun (hs, items) raw ->
         handle_handshake hs.machina hs raw
         >|= fun (hs', items') -> (hs', items @ items'))
       (hs, []) hss
     >|= fun (hs, items) ->
       ({ hs with hs_fragment }, items, None, `Pass, `No_err)

  | Packet.HEARTBEAT -> fail (`Fatal `NoHeartbeat)


(* the main thingy *)
let handle_raw_record state (hdr, buf as record : raw_record) =

  Tracing.sexpf ~tag:"record-in" ~f:sexp_of_raw_record record ;

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
  >|= fun (handshake, items, data, dec_cmd, err) ->
  let (encryptor, encs) =
    List.fold_left (fun (st, es) -> function
      | `Change_enc st' -> (st', es)
      | `Record r       ->
          let (st', enc) = encrypt_records st handshake.protocol_version [r] in
          (st', es @ enc))
    (state.encryptor, [])
    items
  in
  let decryptor = match dec_cmd with
    | `Change_dec dec -> dec
    | `Pass           -> dec_st in
  let state' = { state with handshake ; encryptor ; decryptor } in

  Tracing.sexpfs ~tag:"record-out" ~f:sexp_of_record encs ;

  (state', encs, data, err)

let maybe_app a b = match a, b with
  | Some x, Some y -> Some (x <+> y)
  | Some x, None   -> Some x
  | None  , Some y -> Some y
  | None  , None   -> None

let assemble_records (version : tls_version) : record list -> Cstruct.t =
  o Cs.appends @@ List.map @@ Writer.assemble_hdr version

(* main entry point *)
let handle_tls state buf =

  (* Tracing.sexpf ~tag:"state-in" ~f:sexp_of_state state ; *)

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
          Tracing.sexpf ~tag:"eof-out" ~f:Sexplib.Conv.sexp_of_unit () ;
          `Eof
        | `Alert al ->
          Tracing.sexpf ~tag:"ok-alert-out" ~f:sexp_of_tls_alert (Packet.FATAL, al) ;
          `Alert al
        | `No_err ->
          Tracing.sexpf ~tag:"state-out" ~f:sexp_of_state state ;
          `Ok state
      in
      `Ok (res, `Response resp, `Data data)
  | Error x ->
      let version = state.handshake.protocol_version in
      let alert   = alert_of_failure x in
      let resp    = assemble_records version [Alert.make alert] in
      Tracing.sexpf ~tag:"fail-alert-out" ~f:sexp_of_tls_alert (Packet.FATAL, alert) ;
      Tracing.sexpf ~tag:"failure" ~f:sexp_of_failure x ;
      `Fail (x, `Response resp)

let send_records (st : state) records =
  let version = st.handshake.protocol_version in
  let (encryptor, encs) =
    encrypt_records st.encryptor version records in
  let data = assemble_records version encs in
  ({ st with encryptor }, data)

(* utility for user *)
let can_handle_appdata s = hs_can_handle_appdata s.handshake

let handshake_in_progress s =
  match s.handshake.machina with
  | Server Established
  | Client ClientInitial
  | Client Established -> false
  | _                  -> true

(* another entry for user data *)
let send_application_data st css =
  match can_handle_appdata st with
  | true ->
     Tracing.css ~tag:"application-data-out" css ;
     let datas = match st.encryptor with
       (* Mitigate implicit IV in CBC mode: prepend empty fragment *)
       | Some { cipher_st = CBC { iv_mode = Iv _ } } -> Cstruct.create 0 :: css
       | _                                           -> css
     in
     let ty = Packet.APPLICATION_DATA in
     let data = List.map (fun cs -> (ty, cs)) datas in
     Some (send_records st data)
  | false -> None

let send_close_notify st = send_records st [Alert.close_notify]

let reneg st =
  let hs = st.handshake in
  match hs.machina with
  | Server Established ->
     ( match Handshake_server.hello_request hs with
       | Ok (handshake, [`Record hr]) -> Some (send_records { st with handshake } [hr])
       | _                            -> None )
  | Client Established ->
     ( match Handshake_client.answer_hello_request hs with
       | Ok (handshake, [`Record ch]) -> Some (send_records { st with handshake } [ch])
       | _                            -> None )
  | _                        -> None

let client config =
  let config = Config.of_client config in
  let state = new_state config `Client in
  let dch, version = Handshake_client.default_client_hello config in
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
    | TLS_1_0 -> ([Packet.TLS_EMPTY_RENEGOTIATION_INFO_SCSV], [])
    | TLS_1_1 | TLS_1_2 -> ([], [SecureRenegotiation (Cstruct.create 0)])
  in

  let client_hello =
    { dch with
        ciphersuites = dch.ciphersuites @ ciphers ;
        extensions   = extensions @ dch.extensions }
  in

  let ch = ClientHello client_hello in
  let raw = Writer.assemble_handshake ch in
  let machina = AwaitServerHello (client_hello, [raw]) in

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

  (* Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake ch ; *)
  Tracing.sexpf ~tag:"state-out" ~f:sexp_of_state state ;
  send_records state [(Packet.HANDSHAKE, raw)]

let server config = new_state Config.(of_server config) `Server

open Sexplib
open Sexplib.Conv

type epoch_data = {
  protocol_version : tls_version ;
  ciphersuite      : Ciphersuite.ciphersuite ;
  peer_certificate : X509.Certificate.certificate list ;
  peer_name        : string option ;
  trust_anchor     : X509.Certificate.certificate option ;
  own_certificate  : X509.Certificate.certificate list ;
  own_private_key  : Nocrypto.Rsa.priv option ;
  own_name         : string option ;
  master_secret    : master_secret ;
} with sexp

type epoch = [
  | `InitialEpoch
  | `Epoch of epoch_data
] with sexp

let epoch state =
  let hs = state.handshake in
  match hs.session with
  | []           -> `InitialEpoch
  | session :: _ ->
     `Epoch {
        protocol_version = hs.protocol_version ;
        ciphersuite      = session.ciphersuite ;
        peer_certificate = session.peer_certificate ;
        peer_name        = Config.(hs.config.peer_name) ;
        trust_anchor     = session.trust_anchor ;
        own_certificate  = session.own_certificate ;
        own_private_key  = session.own_private_key ;
        own_name         = session.own_name ;
        master_secret    = session.master_secret ;
      }
