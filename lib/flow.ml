open Core
open Nocrypto

(* some config parameters *)
type config = {
  ciphers          : Ciphersuite.ciphersuite list ;
  protocol_version : tls_version
}

let default_config = {
  ciphers          = Ciphersuite.([TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
                                   TLS_RSA_WITH_3DES_EDE_CBC_SHA (* ;
                                   TLS_RSA_WITH_RC4_128_SHA ;
                                   TLS_RSA_WITH_RC4_128_MD5 *) ]) ;
  protocol_version = TLS_1_1
}

let protocol_version_cstruct =
  Writer.assemble_protocol_version default_config.protocol_version

let supported_protocol_version v =
  default_config.protocol_version <= v

module Or_alert =
  Control.Or_error_make (struct type err = Packet.alert_type end)
open Or_alert

let fail_false v err =
  match v with
  | true ->  return ()
  | false -> fail err

let fail_neq cs1 cs2 err =
  fail_false (Utils.cs_eq cs1 cs2) err

type iv_mode =       (* IV style *)
  | Iv of Cstruct.t  (* traditional CBC *)
  | Random_iv        (* tls 1.1 style *)

type cipher_st =
  | Stream : 'k Crypto.stream_cipher * 'k -> cipher_st
  | CBC    : 'k Crypto.cbc_cipher * 'k * iv_mode -> cipher_st
(*   | GCM : ... *)

type crypto_context = {
  sequence  : int64 ;
  cipher_st : cipher_st ;
  mac       : Crypto.hash_fn * Cstruct.t
}

type crypto_state = crypto_context option

type connection_end = Server | Client

type dh_state = [
    `Initial
  | `Sent     of DH.group * DH.secret
  | `Received of DH.group * Cstruct.t
]

type security_parameters = {
  entity                : connection_end ;
  ciphersuite           : Ciphersuite.ciphersuite ;
  master_secret         : Cstruct.t ;
  client_random         : Cstruct.t ;
  server_random         : Cstruct.t ;
  dh_state              : dh_state ;
  server_certificate    : Asn_grammars.certificate option ;
  client_verify_data    : Cstruct.t ;
  server_verify_data    : Cstruct.t ;
  server_name           : string option ;
}


let print_security_parameters sp =
  let open Printf in
  Printf.printf "ocaml-tls (secure renogiation enforced, session id ignored)\n";
  Printf.printf "protocol %s\n" (Printer.tls_version_to_string default_config.protocol_version);
  Printf.printf "cipher %s\n" (Ciphersuite.ciphersuite_to_string sp.ciphersuite);
  Printf.printf "master secret";
  Cstruct.hexdump sp.master_secret;

(* EVERYTHING a well-behaved dispatcher needs. And pure, too. *)
type tls_internal_state = [
  | `Initial
  | `Handshaking of security_parameters * Cstruct.t list
  | `KeysExchanged of crypto_state * crypto_state * security_parameters * Cstruct.t list (* only used in server, client initiates change cipher spec *)
  | `Established of security_parameters
]

let state_to_string = function
  | `Initial         -> "Initial"
  | `Handshaking _   -> "Shaking hands"
  | `KeysExchanged _ -> "Keys are exchanged"
  | `Established _   -> "Established"

type record = Packet.content_type * Cstruct.t


(* this is the externally-visible state somebody will keep track of for us. *)
type state = {
  machina   : tls_internal_state ;
  decryptor : crypto_state ;
  encryptor : crypto_state ;
  fragment  : Cstruct.t ;
}

let empty_state = {
  machina   = `Initial ;
  decryptor = None ;
  encryptor = None ;
  fragment  = Cstruct.create 0
}

(* well-behaved pure encryptor *)

let encrypt (st : crypto_state) ty buf =
  let version = default_config.protocol_version in (* XXX *)

  match st with
  | None     -> (st, buf)
  | Some ctx ->
      let signature =
        let ver = pair_of_tls_version version in
        Crypto.signature ctx.mac ctx.sequence ty ver buf in

      let to_encrypt = buf <> signature in

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
            (CBC (m, key, Random_iv), iv <> message)

      in
      let ctx' =
        { ctx with sequence  = Int64.succ ctx.sequence ;
                   cipher_st = st' } in
      (Some ctx', enc)


let verify_mac { mac = (hash, _) as mac ; sequence } ty ver decrypted =
  let macstart = Cstruct.len decrypted - Crypto.digest_size hash in
  if macstart <= 0 then fail Packet.BAD_RECORD_MAC else
    let (body, mmac) = Cstruct.split decrypted macstart in
    let cmac =
      let ver = pair_of_tls_version ver in
      Crypto.signature mac sequence ty ver body in
    fail_neq cmac mmac Packet.BAD_RECORD_MAC >>= fun () -> return body


let decrypt (st : crypto_state) ty buf =
  let version = default_config.protocol_version in (* XXX *)

  let verify ctx (st', dec) =
    verify_mac ctx ty version dec >>= fun body -> return (st', body)

  (* This comment is borrowed from miTLS, but applies here as well: *)
  (* We implement standard mitigation for padding oracles.
     Still, we note a small timing leak here:
     The time to verify the mac is linear in the plaintext length. *)
  (* defense against
     http://lasecwww.epfl.ch/memo/memo_ssl.shtml
     1) in https://www.openssl.org/~bodo/tls-cbc.txt *)
  (* hmac is computed in this failure branch from the encrypted data,
     in the successful branch it is decrypted - padding (which is smaller equal
     than encrypted data) *)
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
        (* XXX check for length! *)
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
        let ctx' = { ctx with sequence  = Int64.succ ctx.sequence ;
                              cipher_st = st' } in
        return (Some ctx', msg)


(* party time *)
let rec separate_records : Cstruct.t ->  ((tls_hdr * Cstruct.t) list * Cstruct.t) or_error
= fun buf ->
  match (Cstruct.len buf) > 5 with
  | false -> return ([], buf)
  | true  ->
     match Reader.parse_hdr buf with
     | Reader.Or_error.Ok (_, buf', len) when len > (Cstruct.len buf') ->
        return ([], buf)
     | Reader.Or_error.Ok (hdr, buf', len)                             ->
        separate_records (Cstruct.shift buf' len) >>= fun (tl, frag) ->
        return ((hdr, (Cstruct.sub buf' 0 len)) :: tl, frag)
     | Reader.Or_error.Error _                                         ->
        fail Packet.HANDSHAKE_FAILURE

let assemble_records : record list -> Cstruct.t =
  o Utils.cs_appends @@ List.map @@ (Writer.assemble_hdr default_config.protocol_version)

type rec_resp = [
  | `Change_enc of crypto_state
  | `Record     of record
]
type dec_resp = [ `Change_dec of crypto_state | `Pass ]

let divide_keyblock ~version key mac iv buf =
  let open Cstruct in
  let c_mac, rt0 = split buf mac in
  let s_mac, rt1 = split rt0 mac in
  let c_key, rt2 = split rt1 key in
  let s_key, rt3 = split rt2 key in
  let c_iv , s_iv = match version with
    | TLS_1_0 -> split rt3 iv
    | TLS_1_1 -> (create 0, create 0)
  in
  (c_mac, s_mac, c_key, s_key, c_iv, s_iv)

let initialize_crypto_ctx sp premaster =

  let open Ciphersuite in
  let version = default_config.protocol_version in

  let master = Crypto.generate_master_secret premaster
                (sp.client_random <> sp.server_random) in

  let key, iv, mac = ciphersuite_cipher_mac_length sp.ciphersuite in
  let kblen = match version with
    | TLS_1_0 -> 2 * key + 2 * mac + 2 * iv
    | TLS_1_1 -> 2 * key + 2 * mac
  in
  let rand = sp.server_random <> sp.client_random in
  let keyblock = Crypto.key_block kblen master rand in

  let c_mac, s_mac, c_key, s_key, c_iv, s_iv =
    divide_keyblock ~version key mac iv keyblock in

  let mac    = ciphersuite_mac sp.ciphersuite in
  let cipher = ciphersuite_cipher sp.ciphersuite in

  let context cipher_k iv mac_k =
    let open Crypto.Ciphers in
    let cipher_st =
      match (get_cipher ~secret:cipher_k cipher, version) with
      | (K_Stream (cip, st), _      ) -> Stream (cip, st)
      | (K_CBC    (cip, st), TLS_1_0) -> CBC (cip, st, Iv iv)
      | (K_CBC    (cip, st), TLS_1_1) -> CBC (cip, st, Random_iv)
    and mac = (get_hash mac, mac_k)
    and sequence = 0L in
    { cipher_st ; mac ; sequence }
  in

  let c_context = context c_key c_iv c_mac
  and s_context = context s_key s_iv s_mac in

  (c_context, s_context, { sp with master_secret = master })


let handle_raw_record handler state (hdr, buf) =
  decrypt state.decryptor hdr.content_type buf >>= fun (dec_st, dec) ->
  handler state.machina hdr.content_type dec >>= fun (machina, items, dec_cmd) ->
  let (encryptor, encs) =
    List.fold_left (fun (st, es) ->
                    function
                    | `Change_enc st' -> (st', es)
                    | `Record (ty, buf) ->
                       let (st', enc) = encrypt st ty buf in
                       (st', es @ [(ty, enc)]))
                   (state.encryptor, [])
                   items
  in
  let decryptor = match dec_cmd with
    | `Change_dec dec -> dec
    | `Pass           -> dec_st
  in
  let fragment = state.fragment in
  return ({ machina ; encryptor ; decryptor ; fragment }, encs)

let alert typ =
  let buf = Writer.assemble_alert typ in
  (Packet.ALERT, buf)

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

type ret = [
  | `Ok of (state * Cstruct.t)
  | `Fail of Cstruct.t
]

let handle_tls_int : (tls_internal_state -> Packet.content_type -> Cstruct.t
      -> (tls_internal_state * rec_resp list * dec_resp) or_error) ->
                 state -> Cstruct.t -> ret
= fun handler state buf ->
  match
    separate_records (state.fragment <> buf) >>= fun (in_records, frag) ->
    foldM (fun (st, raw_rs) r ->
           map (fun (st', raw_rs') -> (st', raw_rs @ raw_rs')) @@
             handle_raw_record handler st r)
          (state, [])
          in_records
    >>= fun (state', out_records) ->
    let buf' = assemble_records out_records in
    return ({ state' with fragment = frag }, buf')
  with
  | Ok v    -> `Ok v
  | Error x -> `Fail (assemble_records [alert x])

let find_hostname : 'a hello -> string option =
  fun h ->
    let hexts = List.filter (function
                               | Hostname names -> true
                               | _              -> false)
                             h.extensions
    in
    match hexts with
    | [Hostname name] -> name
    | _ -> None

let rec check_reneg expected = function
  | []                       -> fail Packet.NO_RENEGOTIATION
  | SecureRenegotiation x::_ -> fail_neq expected x Packet.NO_RENEGOTIATION
  | _::xs                    -> check_reneg expected xs

let handle_alert buf =
  match Reader.parse_alert buf with
  | Reader.Or_error.Ok al ->
     Printf.printf "ALERT: %s\n%!" (Printer.alert_to_string al);
     fail Packet.CLOSE_NOTIFY
  | Reader.Or_error.Error _ ->
     Printf.printf "unknown alert";
     Cstruct.hexdump buf;
     fail Packet.UNEXPECTED_MESSAGE
