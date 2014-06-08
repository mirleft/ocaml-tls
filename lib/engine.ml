open Nocrypto

open Utils

open Core
open State


let (<+>) = Utils.Cs.(<+>)

(* user API *)

type state = State.state

type ret = [
  | `Ok   of [ `Ok of state | `Eof | `Alert of Packet.alert_type ] * Cstruct.t * Cstruct.t option
  | `Fail of Packet.alert_type * Cstruct.t
]

let new_state config role =
  let handshake_state = match role with
    | `Client -> Client ClientInitial
    | `Server -> Server ServerInitial (* we should check that a own_cert is Some _ in config! *)
  in
  let handshake = {
    version      = max_protocol_version Config.(config.protocol_versions) ;
    rekeying     = None ;
    machina      = handshake_state ;
    config       = config ;
    hs_fragment  = Cstruct.create 0 ;
  }
  in
  {
    handshake = handshake ;
    decryptor = None ;
    encryptor = None ;
    fragment  = Cstruct.create 0 ;
  }

type raw_record = tls_hdr * Cstruct_s.t with sexp

(* Tracing converters. *)

let sexp_of_records = Sexplib.Conv.sexp_of_list sexp_of_record

(* well-behaved pure encryptor *)
let encrypt (version : tls_version) (st : crypto_state) ty buf =
  match st with
  | None     -> (st, buf)
  | Some ctx ->
      let signature =
        let ver = pair_of_tls_version version in
        Crypto.mac ctx.mac ctx.sequence ty ver buf in

      let to_encrypt = buf <+> signature in

      let (st', enc) =
        match ctx.cipher_st with

        | Stream (m, key) ->
            let (message, key') =
              Crypto.encrypt_stream ~cipher:m ~key to_encrypt in
            (Stream (m, key'), message)

        | CBC (m, key, Iv iv) ->
            let (message, iv') =
              Crypto.encrypt_cbc ~cipher:m ~key ~iv to_encrypt in
            (CBC (m, key, Iv iv'), message)

        | CBC (m, key, Random_iv) ->
            let iv = Rng.generate (Crypto.cbc_block m) in
            let (message, _) =
              Crypto.encrypt_cbc ~cipher:m ~key ~iv to_encrypt in
            (CBC (m, key, Random_iv), iv <+> message)

      in
      let ctx' = { ctx with
                     sequence  = Int64.succ ctx.sequence ;
                     cipher_st = st' }
      in
      (Some ctx', enc)

(* well-behaved pure decryptor *)
let verify_mac { mac = (hash, _) as mac ; sequence } ty ver decrypted =
  let macstart = Cstruct.len decrypted - Crypto.digest_size hash in
  if macstart < 0 then fail Packet.BAD_RECORD_MAC else
    let (body, mmac) = Cstruct.split decrypted macstart in
    let cmac =
      let ver = pair_of_tls_version ver in
      Crypto.mac mac sequence ty ver body in
    guard (Cs.equal cmac mmac) Packet.BAD_RECORD_MAC >|= fun () -> body


let decrypt (version : tls_version) (st : crypto_state) ty buf =

  let verify ctx (st', dec) =
    verify_mac ctx ty version dec >>= fun body -> return (st', body)

  (* hmac is computed in this failure branch from the encrypted data, in the
     successful branch it is decrypted - padding (which is smaller equal than
     encrypted data) *)
  (* This comment is borrowed from miTLS, but applies here as well: *)
  (* We implement standard mitigation for padding oracles. Still, we note a
     small timing leak here: The time to verify the mac is linear in the
     plaintext length. *)
  (* defense against http://lasecwww.epfl.ch/memo/memo_ssl.shtml 1) in
     https://www.openssl.org/~bodo/tls-cbc.txt *)
  and mask_decrypt_failure ctx =
    verify_mac ctx ty version buf >>= fun _ -> fail Packet.BAD_RECORD_MAC
  in

  let dec ctx =
    match ctx.cipher_st with

    | Stream (m, key) ->
        let (message, key') = Crypto.decrypt_stream ~cipher:m ~key buf in
        verify ctx (Stream (m, key'), message)

    | CBC (m, key, Iv iv) ->
      ( match Crypto.decrypt_cbc ~cipher:m ~key ~iv buf with
        | None            -> mask_decrypt_failure ctx
        | Some (dec, iv') ->
            let st' = CBC (m, key, Iv iv') in
            verify ctx (st', dec) )

    | CBC (m, key, Random_iv) ->
        if Cstruct.len buf < Crypto.cbc_block m then
          fail Packet.BAD_RECORD_MAC
        else
          let (iv, buf) = Cstruct.split buf (Crypto.cbc_block m) in
          match Crypto.decrypt_cbc ~cipher:m ~key ~iv buf with
            | None          -> mask_decrypt_failure ctx
            | Some (dec, _) ->
                let st' = CBC (m, key, Random_iv) in
                verify ctx (st', dec)

  in
  match st with
  | None     -> return (st, buf)
  | Some ctx ->
      dec ctx >>= fun (st', msg) ->
      let ctx' = { ctx with
                     sequence  = Int64.succ ctx.sequence ;
                     cipher_st = st' }
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
       fail Packet.RECORD_OVERFLOW
    | (Some _, Some _, size) when size > len payload       ->
       return ([], buf)
    | (Some content_type, Some version, size)              ->
       separate_records (shift payload size) >|= fun (tl, frag) ->
       let packet = ({ content_type ; version }, sub payload 0 size) in
       (packet :: tl, frag)
    | (_, None, _)                                         ->
       fail Packet.PROTOCOL_VERSION
    | (None, _, _)                                         ->
       fail Packet.UNEXPECTED_MESSAGE


let encrypt_records encryptor version records =
  let open Packet in
  let rec merge = function
    | []                                     -> []
    | (HANDSHAKE, a) :: (HANDSHAKE, b) :: xs -> merge ((HANDSHAKE, a <+> b) :: xs)
    | x::xs                                  -> x :: merge xs

  and split = function
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
  crypt encryptor (split @@ merge records)

module Alert = struct

  open Packet

  let make typ = (ALERT, Writer.assemble_alert typ)

  let close_notify = make CLOSE_NOTIFY

  let handle buf =
    match Reader.parse_alert buf with
    | Reader.Or_error.Ok (_, a_type as alert) ->
      Printf.printf "ALERT: %s\n%!" (Printer.alert_to_string alert);
      let err = match a_type with
        | CLOSE_NOTIFY -> `Eof
        | _            -> `Alert a_type in
      return (err, [`Record close_notify])
    | Reader.Or_error.Error _ ->
      Printf.printf "unknown alert";
      Cstruct.hexdump buf;
      fail Packet.UNEXPECTED_MESSAGE
end

let hs_can_handle_appdata s =
  match s.rekeying with
  | Some _ -> true
  | None   -> false

let rec separate_handshakes buf =
  let open Cstruct in
  if len buf < 4 then
    return ([], buf)
  else
    match Reader.parse_handshake_length buf with
    | size when size > len buf -> return ([], buf)
    | size                     ->
       let hs, rest = split buf (size + 4) in
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
        (hs, None, out, `Pass, err)

  | Packet.APPLICATION_DATA ->
    ( match hs_can_handle_appdata hs with
      | true  -> return (hs, non_empty buf, [], `Pass, `No_err)
      | false -> fail Packet.UNEXPECTED_MESSAGE )

  | Packet.CHANGE_CIPHER_SPEC ->
      handle_change_cipher_spec hs.machina hs buf
      >|= fun (hs, items, dec_cmd) -> (hs, None, items, dec_cmd, `No_err)

  | Packet.HANDSHAKE ->
     separate_handshakes (hs.hs_fragment <+> buf)
     >>= fun (hss, hs_fragment) ->
       foldM (fun (hs, items) raw ->
         handle_handshake hs.machina hs raw
         >|= fun (hs', items') -> (hs', items @ items'))
       (hs, []) hss
     >|= fun (hs, items) ->
       ({ hs with hs_fragment }, None, items, `Pass, `No_err)


(* the main thingy *)
let handle_raw_record state (hdr, buf as record : raw_record) =

  Tracing.sexpf ~tag:"state-in" ~f:sexp_of_state state ;
  Tracing.sexpf ~tag:"record-in" ~f:sexp_of_raw_record record ;

  let hs = state.handshake in
  let version = hs.version in
  ( match hs.machina, hdr.version = version with
    | Client (ClientHelloSent _), _     -> return ()
    | Server (ServerInitial)    , _     -> return ()
    | _                         , true  -> return ()
    | _                         , false -> fail Packet.PROTOCOL_VERSION )
  >>= fun () ->
  decrypt version state.decryptor hdr.content_type buf
  >>= fun (dec_st, dec) ->
  handle_packet state.handshake dec hdr.content_type
  >|= fun (handshake, data, items, dec_cmd, err) ->
  let (encryptor, encs) =
    List.fold_left (fun (st, es) -> function
      | `Change_enc st' -> (st', es)
      | `Record r       ->
          let (st', enc) = encrypt_records st handshake.version [r] in
          (st', es @ enc))
    (state.encryptor, [])
    items
  in
  let decryptor = match dec_cmd with
    | `Change_dec dec -> dec
    | `Pass           -> dec_st in
  let state' = { state with handshake ; encryptor ; decryptor } in

  Tracing.sexpf ~tag:"state-out" ~f:sexp_of_state state ;
  Tracing.sexpf ~tag:"record-out" ~f:sexp_of_records encs ;

  (state', data, encs, err)

let maybe_app a b = match a, b with
  | Some x, Some y -> Some (x <+> y)
  | Some x, None   -> Some x
  | None  , Some y -> Some y
  | None  , None   -> None

let assemble_records (version : tls_version) : record list -> Cstruct.t =
  o Utils.Cs.appends @@ List.map @@ Writer.assemble_hdr version

(* main entry point *)
let handle_tls state buf =

  let rec handle_records st = function
    | []    -> return (st, None, [], `No_err)
    | r::rs ->
        handle_raw_record st r >>= function
          | (st, data, raw_rs, `No_err) ->
              handle_records st rs >|= fun (st', data', raw_rs', err') ->
                (st', maybe_app data data', raw_rs @ raw_rs', err')
          | res -> return res
  in
  match
    separate_records (state.fragment <+> buf)
    >>= fun (in_records, fragment) ->
      handle_records state in_records
    >|= fun (state', data, out_records, err) ->
      let version = state'.handshake.version in
      let buf'    = assemble_records version out_records in
      ({ state' with fragment }, buf', data, err)
  with
  | Ok (state, data, resp, err) ->
      let res = match err with
        | `Eof | `Alert _ as err -> err
        | `No_err                -> `Ok state in
      `Ok (res, data, resp)
  | Error x ->
      let version    = state.handshake.version in
      let alert_resp = assemble_records version [Alert.make x] in
      `Fail (x, alert_resp)

let send_records (st : state) records =
  let version = st.handshake.version in
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
     let datas = match st.encryptor with
       (* Mitigate implicit IV in CBC mode: prepend empty fragment *)
       | Some { cipher_st = CBC (_, _, Iv _) } -> Cstruct.create 0 :: css
       | _                                     -> css
     in
     let ty = Packet.APPLICATION_DATA in
     let data = List.map (fun cs -> (ty, cs)) datas in
     Some (send_records st data)
  | false -> None

let send_close_notify st = send_records st [Alert.close_notify]

let client config =
  let config = Config.of_client config in

  let state = new_state config `Client in

  let dch, params = Handshake_client.default_client_hello config in

  let secure_rekeying = SecureRenegotiation (Cstruct.create 0) in

  let ciphers, extensions = match dch.version with
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
    | TLS_1_0 -> ([Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV], [])
    | TLS_1_1 | TLS_1_2 -> ([], [secure_rekeying])
  in

  let client_hello =
    { dch with
        ciphersuites = dch.ciphersuites @ ciphers ;
        extensions   = extensions @ dch.extensions }
  in

  let raw = Writer.assemble_handshake (ClientHello client_hello) in
  let machina = ClientHelloSent (client_hello, params, [raw]) in
  let handshake = { state.handshake with machina = Client machina } in
  send_records
      { state with handshake }
      [(Packet.HANDSHAKE, raw)]

let server config = new_state Config.(of_server config) `Server

