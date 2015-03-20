open Tracer_common
open Read_trace

open Tls
open State

open Nocrypto
open Nocrypto.Dh
let to_cstruct_sized { p; _ } z =
  Numeric.Z.(to_cstruct_be ~size:(Uncommon.cdiv (bits p) 8) z)

let public_of_secret (({ p; gg; _ } as group), { x }) =
  to_cstruct_sized group Z.(powm gg x p)

let dbg_fail f = Sexplib.Sexp.to_string_hum (Engine.sexp_of_failure f)

let dbg_cc c = Printf.printf "cc %s\n" (Sexplib.Sexp.to_string_hum (sexp_of_crypto_state c))


let find_out ?packet (trace : trace list) =
  let tst data = Cstruct.len data > 0 in
  let tstt t = match packet with None -> true | Some x when x = t -> true | _ -> false in
  match
    find_trace
      (function `RecordOut (t, d) when tstt t && tst d -> true | _ -> false)
      trace
  with
  | Some (`RecordOut r) -> Some r
  | _ -> None

let find_hs_out dec ver t =
  if
    (dec = None) ||
    (try (
       let sout = List.find (function `StateOut _ -> true | _ -> false) t in
       match sout with
       | `StateOut sout -> ver = sout.handshake.protocol_version
       | _ -> true)
     with Not_found -> true)
  then
    find_out ~packet:Packet.HANDSHAKE t
  else
    None

let parse_server_hello out =
  match Reader.parse_handshake_frame out with
  | None, _ -> assert false
  | Some data, _ ->
    match Reader.parse_handshake data with
    | Reader.Or_error.Ok Core.ServerHello sh -> sh
    | _ -> assert false

let find_dh_sent (trace : trace list) =
  match
    find_trace
      (function
        | `StateOut st ->
          ( match st.handshake.machina with
            | Server (AwaitClientKeyExchange_DHE_RSA _) -> true
            | Server (AwaitClientCertificate_DHE_RSA _) -> true
            | _ -> false )
        | _ -> false)
      trace
  with
  | Some (`StateOut st) ->
    ( match st.handshake.machina with
      | Server (AwaitClientKeyExchange_DHE_RSA (_, dh_sent, _)) ->
        let group, secret = dh_sent in
        Some (group, secret, public_of_secret dh_sent)
      | Server (AwaitClientCertificate_DHE_RSA (_, dh_sent, _)) ->
        let group, secret = dh_sent in
        Some (group, secret, public_of_secret dh_sent)
      | _ -> None )
  | _ -> None


(* configured is the range (min, max) -- chosen is the one from server hello -- requested the one from client hello  *)
(* sanity: min >= chosen >= max ; requested >= chosen *)
let version_agreed configured chosen requested =
  match Handshake_common.supported_protocol_version configured (Core.Supported chosen) with
  | None -> fail (`Error (`NoConfiguredVersion chosen))
  | Some _ ->
    if Core.version_ge requested chosen then
      return chosen
    else
      fail (`Error (`NoConfiguredVersion chosen))

(* again, chosen better be part of configured -- and also chosen be a mem of requested *)
(* this is slightly weak -- depending on sni / certificate we have to limit the decision *)
let cipher_agreed _certificates configured chosen requested =
  if List.mem chosen configured &&
     List.mem chosen (Utils.filter_map ~f:Ciphersuite.any_ciphersuite_to_ciphersuite requested)
  then
    return chosen
  else
    fail (`Error (`NoConfiguredCiphersuite [chosen]))

let fixup_initial_state state raw next =
  let server_hello = parse_server_hello raw in
  (*Printf.printf "server hello is %s\n" (Sexplib.Sexp.to_string_hum (Core.sexp_of_server_hello server_hello)) ; *)
  let dh_sent = match Ciphersuite.ciphersuite_kex server_hello.Core.ciphersuites with
    | Ciphersuite.RSA -> None
    | Ciphersuite.DHE_RSA -> find_dh_sent next
  in
  let config = state.handshake.config in
  let choices = {
      version = version_agreed config.Config.protocol_versions server_hello.Core.version ;
      cipher = cipher_agreed config.Config.own_certificates config.Config.ciphers server_hello.Core.ciphersuites ;
      fallback = (fun _ _ -> return ()) ;
      random = (fun () -> server_hello.Core.random) ;
      session_id = (fun () -> server_hello.Core.sessionid) ;
      dh_secret = (fun () -> dh_sent)
    }
  in
  (choices, server_hello.Core.version)

let check_stream = function
  | None -> false
  | Some x -> match x.cipher_st with
    | Stream _ -> true
    | _ -> false

let normalise crypt ver data =
  match Engine.separate_records data with
  | Ok (xs, rest) ->
    assert (Cstruct.len rest = 0) ;
    (* Printf.printf "now trying to decrypt %d packets\n" (List.length xs) ; *)
    let e, acc = List.fold_left (fun (enc, acc) (hdr, data) ->
        (* dbg_cc enc; Cstruct.hexdump data ; *)
        match Engine.decrypt ver enc hdr.Core.content_type data with
        | Ok (enc, d) ->
          (* Printf.printf "dec is %d\n" (Cstruct.len d) ; Cstruct.hexdump d ; *)
          (enc, (hdr, d) :: acc)
        | Error e ->
          if hdr.Core.content_type == Packet.CHANGE_CIPHER_SPEC (* && Cstruct.len data = 1 *) then
            (* we're a bit unlucky, but let's pretend to be good *)
            let ccs = Writer.assemble_change_cipher_spec in
            (enc, (hdr, ccs) :: acc)
          else
            (Printf.printf "dec failed %s\n" (dbg_fail e) ;
             dbg_cc enc ;
             Printf.printf "ver %s\nmac" (Printer.tls_version_to_string ver) ;
             (match enc with
              | Some x -> (match x.cipher_st with
                  | CBC c -> Cstruct.hexdump c.hmac_secret
                  | _ -> ())
              | _ -> ()) ;
             Cstruct.hexdump data ;
             assert false))
        (crypt, []) xs
    in
    (List.rev acc, e)
  | _ -> assert false


open Sexplib.Conv

type ret =
  | End_of_trace of int
  | Handle_alert of string
  | Alert_in of string
  | Stream_enc
  | No_handshake_out
  | Comparison_failed
  | Alert_out_success
  | Alert_out_different of Packet.alert_type * Packet.alert_type
  | Alert_out_fail of Packet.alert_type
with sexp

(* TODO *)
(* pass extension types in choices! *)
(* what happens if handle didn't produce an output, but record-out came along? -- need a way to passthrough / match these as well! *)
(* alert/failure traces *)
let rec replay ?choices prev_state state pending_out t ccs alert_out check =
  let handle_and_rec ?choices state hdr data xs =
    (* Printf.printf "now handling...\n" ; dbg_cc state.decryptor ; *)
    match Engine.handle_tls ?choices state (fixup_in_record hdr data) with
    | `Ok (`Ok state', `Response out, `Data data) ->
      let pending = match out with
        | None -> (* Printf.printf "empty out!?\n"; *) pending_out
        | Some out ->
          (* Printf.printf "output from handle_tls, normalising\n" ; *)
          let ver = state.handshake.protocol_version in
          let data, _ = normalise state.encryptor ver out in
          pending_out @ data
      in
      let prev, ccs = match hdr.Core.content_type with
        | Packet.CHANGE_CIPHER_SPEC -> (state', succ ccs)
        | _ -> (prev_state, ccs)
      in
      ( match data with
        | None -> replay ?choices prev state' pending xs ccs alert_out check
        | Some x ->
          (* Printf.printf "received data %s\n" (Cstruct.to_string x); *)
          if check_stream state.encryptor then
            Stream_enc
          else
            replay ?choices prev state' pending xs ccs alert_out check)
    | `Ok _ -> Printf.printf "some ok here" ; assert false
    | `Fail (e, al) ->
      (* in the trace we better have an alert as well! *)
      match alert_out with
      | None ->
        (* Printf.printf "sth failed %s\n" (dbg_fail e) ; *)
        Handle_alert (dbg_fail e)
      | Some x ->
        let al = Engine.alert_of_failure e in
        if snd x = al then
          Alert_out_success
        else
          Alert_out_different (snd x, al)
  in

  match t with
  | (`RecordIn (hdr, data))::xs ->
    (* Printf.printf "record-in %s\n" (Packet.content_type_to_string hdr.Core.content_type) ; *)
    ( match hdr.Core.content_type with
      | Packet.HANDSHAKE ->
        let enc = fixup_in_record hdr data in
        let ver = state.handshake.protocol_version in
        (* Printf.printf "normalising in record-in to find whether it is a clienthello\n"; *)
        let dec, _ = normalise state.decryptor ver enc in
        ( match dec with
          | (_,x)::_ when Cstruct.get_uint8 x 0 = 1->
            (* Printf.printf "decrypted (%d):" (Cstruct.len x) ; Cstruct.hexdump x ; *)
            ( match find_hs_out state.decryptor ver xs with
              | Some (t, out) ->
                let out_data = Writer.assemble_hdr ver (t, out) in
                (* Printf.printf "normalising out_data\n" ; *)
                ( match normalise prev_state.encryptor ver out_data with
                  | (_,x)::_,_ ->
                    assert (Cstruct.get_uint8 x 0 = 2) ;
                    let choices, version = fixup_initial_state state x xs in
                    handle_and_rec ~choices state hdr data xs
                  | _ -> assert false )
              | None ->
                if List.length xs < 3 then
                  ((* Printf.printf "couldn't find handshake out, but trace isn't too long..\n" ; *)
                   No_handshake_out)
                else
                  assert false )
          | _ -> handle_and_rec ?choices state hdr data xs )
      | Packet.ALERT -> (* Printf.printf "alert in! success\n" ; *)
        let enc = fixup_in_record hdr data in
        let ver = state.handshake.protocol_version in
        let dec, _ = normalise state.decryptor ver enc in
        let _ = Engine.handle_tls ?choices state enc in
        ( match dec with
          | (_,x)::_ ->
            ( match Reader.parse_alert x with
              | Reader.Or_error.Ok (_, t) -> Alert_in (Packet.alert_type_to_string t)
              | _ -> Alert_in (Printf.sprintf "unknown alert %d" (Cstruct.get_uint8 data 1) ))
          | _ -> Alert_in (Printf.sprintf "unknown alert' %d" (Cstruct.get_uint8 data 1)) )
      | _ -> handle_and_rec ?choices state hdr data xs )
  | (`RecordOut (t, data))::xs ->
    let rec cmp_data expected rcvd k =
      match expected, rcvd with
      | [], [] -> k []
      | [], _ -> assert false
      | exp::xs, rcv::ys ->
        (* Printf.printf "comparing out %d vs %d\n" (Cstruct.len x) (Cstruct.len y) ; *)
        (* if not (Nocrypto.Uncommon.Cs.equal x y) then
          (Printf.printf "mismatch! (computed)" ; Cstruct.hexdump x ; Printf.printf "stored" ; Cstruct.hexdump y ;
           assert false) ; *)
        (match Tracer_comparison.record_equal exp rcv with
         | (false, _) ->
           Printf.printf "mismatched records!\n";
           Comparison_failed
         | (true, None) -> cmp_data xs ys k
         | (true, Some left) -> cmp_data (left @ xs) ys k )
      | xs, [] -> k xs
    in
    let version = state.handshake.protocol_version in
    let data = Writer.assemble_hdr version (t, data) in
    (* Printf.printf "record out, normalising\n" ; *)
    let ver = state.handshake.protocol_version in
    let data, e = normalise prev_state.encryptor ver data in
    if check then
      cmp_data pending_out data (fun leftover ->
          replay ?choices { prev_state with encryptor = e } state leftover xs ccs alert_out check)
    else
      replay ?choices { prev_state with encryptor = e } state [] xs ccs alert_out check

  | (`StateIn s)::xs ->
    let maybe_seq recs sin =
      match recs, sin with
      | Some st, Some sin ->
        let sequence = sin.sequence in
        let cipher_st =
          if sequence = 0L then
            st.cipher_st
          else
            match st.cipher_st, sin.cipher_st with
            | Stream s, Stream _ -> Stream s
            | CBC s, CBC t ->
              let iv_mode = match s.iv_mode, t.iv_mode with
                | Random_iv, Random_iv -> Random_iv
                | Iv _, Iv r -> Iv r
                | _ -> assert false
              in
              CBC { s with iv_mode }
            | _ -> assert false
        in
        Some { sequence ; cipher_st }
      | _ -> recs
    in
    let encryptor = maybe_seq prev_state.encryptor s.encryptor
    and decryptor = maybe_seq state.decryptor s.decryptor
    in
    replay ?choices
      { prev_state with encryptor }
      { state with decryptor }
      pending_out xs ccs alert_out check
  | _::xs -> replay ?choices prev_state state pending_out xs ccs alert_out check
  | [] ->
    match alert_out with
    | None ->
      assert (List.length pending_out = 0) ;
      End_of_trace ccs
    | Some x ->
      Alert_out_fail (snd x)
