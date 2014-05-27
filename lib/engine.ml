open Core
open Nocrypto
open Flow
open Flow.Or_alert


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
       separate_records (shift payload size) >>= fun (tl, frag) ->
       let packet = ({ content_type ; version }, sub payload 0 size) in
       return (packet :: tl, frag)
    | (_, None, _)                                         ->
       fail Packet.PROTOCOL_VERSION
    | (None, _, _)                                         ->
       fail Packet.UNEXPECTED_MESSAGE

let handle_raw_record state ((hdr : tls_hdr), buf) =
  let hs = state.handshake in
  let version = hs.version in
  ( match hs.machina, supported_protocol_version hs.config hdr.version with
    | Client (ClientHelloSent _), Some _ -> return ()
    | Server (ServerInitial)    , Some _ -> return ()
    | _, _ when hdr.version = version    -> return ()
    | _, _                               -> fail Packet.PROTOCOL_VERSION )
  >>= fun () ->
  decrypt version state.decryptor hdr.content_type buf
  >>= fun (dec_st, dec) ->
  let hs = state.handshake in
  (match hdr.content_type with
  | Packet.ALERT -> (* this always fails, might be ok to accept some WARNING-level alerts *)
     handle_alert dec
  | Packet.APPLICATION_DATA ->
     ( match can_send_appdata state with
       | true  -> return (hs, Some dec, [], `Pass)
       | false -> fail Packet.UNEXPECTED_MESSAGE
     )
  | Packet.CHANGE_CIPHER_SPEC ->
     ( match hs.machina with
       | Client cs -> Client.handle_change_cipher_spec cs hs dec
       | Server ss -> Server.handle_change_cipher_spec ss hs dec ) >>= fun (hs, items, dec_cmd) ->
     return (hs, None, items, dec_cmd)
  | Packet.HANDSHAKE ->
     ( match hs.machina with
       | Client cs -> Client.handle_handshake cs hs dec
       | Server ss -> Server.handle_handshake ss hs dec ) >>= fun (hs, items, dec) ->
     return (hs, None, items, dec) )
  >>= fun (handshake, data, items, dec_cmd) ->
  let (encryptor, encs) =
    List.fold_left (fun (st, es) -> function
      | `Change_enc st' -> (st', es)
      | `Record (ty, buf) ->
          let (st', enc) = encrypt handshake.version st ty buf in
          (st', es @ [(ty, enc)]))
    (state.encryptor, [])
    items
  in
  let decryptor = match dec_cmd with
    | `Change_dec dec -> dec
    | `Pass           -> dec_st
  in
  let fragment = state.fragment in
  return ({ handshake ; encryptor ; decryptor ; fragment }, data, encs)

type ret = [
  | `Ok   of state * Cstruct.t * Cstruct.t option
  | `Fail of Packet.alert_type * Cstruct.t
]

let maybe_app a b = match a, b with
  | Some x, Some y -> Some (x <+> y)
  | Some x, None   -> Some x
  | None  , Some y -> Some y
  | None  , None   -> None

let handle_tls : state -> Cstruct.t -> ret
= fun state buf ->
  match
    separate_records (state.fragment <+> buf) >>= fun (in_records, frag) ->
    foldM (fun (st, datas, raw_rs) r ->
           map (fun (st', data', raw_rs') -> (st', maybe_app datas data', raw_rs @ raw_rs')) @@
             handle_raw_record st r)
          (state, None, [])
          in_records
    >>= fun (state', data, out_records) ->
    let version = state'.handshake.version in
    let buf' = assemble_records version out_records in
    return ({ state' with fragment = frag }, buf', data)
  with
  | Ok v    -> `Ok v
  | Error x ->
      let version    = state.handshake.version in
      let alert_resp = assemble_records version [alert x] in
      `Fail (x, alert_resp)
