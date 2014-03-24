open Core

(* some config parameters *)
type config = {
  ciphers           : Ciphersuite.ciphersuite list ;
  rng               : int -> Cstruct.t ;
  protocol_versions : tls_version list
}

let default_config = {
  (* this is used as prioritized list of ciphersuites in both client and server code *)
  ciphers           = Ciphersuite.([TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
                                    TLS_RSA_WITH_3DES_EDE_CBC_SHA ;
                                    TLS_RSA_WITH_RC4_128_SHA ;
                                    TLS_RSA_WITH_RC4_128_MD5]) ;
  rng               = (fun n -> Cstruct.create n) ; (* TODO: better random *)
  (* this is an ordered list of all supported versions, highest first *)
  protocol_versions = [TLS_1_1 ; TLS_1_0 ]
}

(* find highest version between !v! and supported versions *)
(* some cases are simple:
  - v is bigger than the highest supported one -> use highest
  - v is an exact match of any supported -> use it!
  - v is smaller than the lowest -> bail *)
(* constraints not checked in code:
    - protocol_versions is ordered from highest to lowest
    - there's no unsupported version between highest and lowest
*)
let supported_protocol_version v =
  let sups = default_config.protocol_versions in
  let highest = List.hd sups in
  if compare v highest >= 0 then
    Some highest
  else
    let lowest = List.nth sups (pred (List.length sups)) in
    if compare v lowest >= 0 then
      Some v
    else
      None

let max_protocol_version = List.hd default_config.protocol_versions

module Or_alert =
  Control.Or_error_make (struct type err = Packet.alert_type end)
open Or_alert

let fail_false v err =
  match v with
  | true ->  return ()
  | false -> fail err

let fail_neq cs1 cs2 err =
  fail_false (Utils.cs_eq cs1 cs2) err

type crypto_context = {
  sequence      : int64 ;
  stream_cipher : Cryptokit.Stream.stream_cipher option ; (* XXX *)
  cipher        : Ciphersuite.encryption_algorithm ;
  cipher_secret : Cstruct.t ;
  cipher_iv     : Cstruct.t ;
  mac           : Ciphersuite.hash_algorithm ;
  mac_secret    : Cstruct.t
}

(* EVERYTHING a cipher needs, be it input or output. And pure, too. *)
type crypto_state = [
  `Nothing
| `Crypted of crypto_context
]

type connection_end = Server | Client

type security_parameters = {
  entity                : connection_end ;
  ciphersuite           : Ciphersuite.ciphersuite ;
  master_secret         : Cstruct.t ;
  client_random         : Cstruct.t ;
  server_random         : Cstruct.t ;
  dh_params             : dh_parameters option ;
  dh_secret             : Cryptokit.DH.private_secret option ;
  server_certificate    : Asn_grammars.certificate option ;
  client_verify_data    : Cstruct.t ;
  server_verify_data    : Cstruct.t ;
  server_name           : string option ;
  protocol_version      : tls_version ;
}

let print_security_parameters sp =
  let open Printf in
  Printf.printf "ocaml-tls (secure renogiation enforced, session id ignored)\n";
  Printf.printf "protocol %s\n" (Printer.tls_version_to_string sp.protocol_version);
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
  decryptor = `Nothing ;
  encryptor = `Nothing ;
  fragment  = Cstruct.create 0
}

let active_protocol_version = function
  | `Initial                     -> max_protocol_version
  | `Handshaking (sp, _)         -> sp.protocol_version
  | `KeysExchanged (_, _, sp, _) -> sp.protocol_version
  | `Established sp              -> sp.protocol_version

(* well-behaved pure encryptor *)
let encrypt : tls_version -> crypto_state -> Packet.content_type -> Cstruct.t -> crypto_state * Cstruct.t
= fun v s ty buf ->
    match s with
    | `Nothing -> (s, buf)
    | `Crypted ctx ->
       let sign = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty (pair_of_tls_version v) buf in
       let to_encrypt = buf <> sign in
       let iv = match ctx.stream_cipher with
         | Some x -> Cstruct.create 0
         | None   -> match v with
                     | TLS_1_0 -> ctx.cipher_iv
                     | TLS_1_1 ->
                        let bs = Ciphersuite.encryption_algorithm_block_size ctx.cipher in
                        default_config.rng bs
       in
       let enc =
         match ctx.stream_cipher with
         | Some x -> Crypto.crypt_stream x to_encrypt
         | None   -> Crypto.encrypt_block ctx.cipher ctx.cipher_secret iv to_encrypt
       in
       let out, next_iv =
         match ctx.stream_cipher with
         | Some _ -> (enc, Cstruct.create 0)
         | None   -> match v with
                     | TLS_1_0 -> (enc, Crypto.last_block ctx.cipher enc)
                     | TLS_1_1 -> (iv <> enc, Cstruct.create 0)
       in
       (`Crypted { ctx with sequence = Int64.succ ctx.sequence ;
                            cipher_iv = next_iv },
        out)

let verify_mac ctx v ty decrypted =
  let macstart = (Cstruct.len decrypted) - (Ciphersuite.hash_length ctx.mac) in
  (* check that macstart > 0! *)
  let body, mac = Cstruct.split decrypted macstart in
  let cmac = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty (pair_of_tls_version v) body in
  fail_neq cmac mac Packet.BAD_RECORD_MAC >>= fun () ->
  return body

(* well-behaved pure decryptor *)
let decrypt : tls_version -> crypto_state -> Packet.content_type -> Cstruct.t -> (crypto_state * Cstruct.t) or_error
= fun v s ty buf ->
    match s with
    | `Nothing -> return (s, buf)
    | `Crypted ctx ->
       ( match ctx.stream_cipher with
         | Some x ->
            let dec = Crypto.crypt_stream x buf in
            verify_mac ctx v ty dec >>= fun (body) ->
            return body
         | None   ->
            let iv, data = match v with
              | TLS_1_0 -> (ctx.cipher_iv, buf)
              | TLS_1_1 ->
                 let bs = Ciphersuite.encryption_algorithm_block_size ctx.cipher in
                 (* check for length! *)
                 Cstruct.split buf bs
            in
            ( match Crypto.decrypt_block ctx.cipher ctx.cipher_secret iv data with
              | None                ->
                 (* This comment is borrowed from miTLS, but applies here as well: *)
                 (* We implement standard mitigation for padding oracles.
                    Still, we note a small timing leak here:
                    The time to verify the mac is linear in the plaintext length. *)
                 (* defense against
                     http://lasecwww.epfl.ch/memo/memo_ssl.shtml
                     1) in https://www.openssl.org/~bodo/tls-cbc.txt *)
                 (* hmac is computed in this failure branch from the encrypted data,
                    in the successful branch it is decrypted - padding (which is smaller equal than encrypted data) *)
                 verify_mac ctx v ty data >>= fun (_body) ->
                 fail Packet.BAD_RECORD_MAC
              | Some dec ->
                 verify_mac ctx v ty dec >>= fun (body) ->
                 return body )
            ) >>= fun (body) ->
       let next_iv = match ctx.stream_cipher with
         | Some _ -> Cstruct.create 0
         | None   -> match v with
                     | TLS_1_0 -> Crypto.last_block ctx.cipher buf
                     | TLS_1_1 -> Cstruct.create 0
       in
       return (`Crypted { ctx with sequence  = Int64.succ ctx.sequence ;
                                   cipher_iv = next_iv },
               body)

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

let assemble_records : tls_version -> record list -> Cstruct.t = fun v ->
  o Utils.cs_appends @@ List.map @@ (Writer.assemble_hdr v)

type rec_resp = [
  | `Change_enc of crypto_state
  | `Record     of record
]
type dec_resp = [ `Change_dec of crypto_state | `Pass ]

let divide_keyblock v key mac iv buf =
  let c_mac, rt0 = Cstruct.split buf mac in
  let s_mac, rt1 = Cstruct.split rt0 mac in
  let c_key, rt2 = Cstruct.split rt1 key in
  let s_key, rt3 = Cstruct.split rt2 key in
  let c_iv , s_iv = match v with
    | TLS_1_0 -> Cstruct.split rt3 iv
    | TLS_1_1 -> Cstruct.(create 0, create 0)
  in
  (c_mac, s_mac, c_key, s_key, c_iv, s_iv)

let initialise_crypto_ctx : security_parameters -> Cstruct.t -> (crypto_context * crypto_context * security_parameters)
 = fun sp premastersecret ->
     let mastersecret = Crypto.generate_master_secret premastersecret (sp.client_random <> sp.server_random) in

     let key, iv, mac = Ciphersuite.ciphersuite_cipher_mac_length sp.ciphersuite in
     let kblen = match sp.protocol_version with
       | TLS_1_0 -> 2 * key + 2 * mac + 2 * iv
       | TLS_1_1 -> 2 * key + 2 * mac
     in
     let rand = sp.server_random <> sp.client_random in
     let keyblock = Crypto.key_block kblen mastersecret rand in

     let c_mac, s_mac, c_key, s_key, c_iv, s_iv =
       divide_keyblock sp.protocol_version key mac iv keyblock in

     let mac = Ciphersuite.ciphersuite_mac sp.ciphersuite in
     let sequence = 0L in
     let cipher = Ciphersuite.ciphersuite_cipher sp.ciphersuite in

     let c_stream_cipher, s_stream_cipher =
       match cipher with
       | Ciphersuite.RC4_128 ->
          let ccipher = Crypto.prepare_arcfour c_key in
          let scipher = Crypto.prepare_arcfour s_key in
          (Some ccipher, Some scipher)
       | _ -> (None, None)
     in

     let c_context =
       { stream_cipher = c_stream_cipher ;
         cipher_secret = c_key ;
         cipher_iv     = c_iv ;
         mac_secret    = c_mac ;
         cipher ; mac ; sequence } in
     let s_context =
       { stream_cipher = s_stream_cipher ;
         cipher_secret = s_key ;
         cipher_iv     = s_iv ;
         mac_secret    = s_mac ;
         cipher ; mac ; sequence } in
     (c_context, s_context, { sp with master_secret = mastersecret })


let handle_raw_record handler state (hdr, buf) =
  let version = active_protocol_version state.machina in
  decrypt version state.decryptor hdr.content_type buf >>= fun (dec_st, dec) ->
  handler state.machina hdr.content_type dec >>= fun (machina, items, dec_cmd) ->
  let version = active_protocol_version machina in
  let (encryptor, encs) =
    List.fold_left (fun (st, es) ->
                    function
                    | `Change_enc st' -> (st', es)
                    | `Record (ty, buf) ->
                       let (st', enc) = encrypt version st ty buf in
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
    let buf' = assemble_records (active_protocol_version state'.machina) out_records in
    return ({ state' with fragment = frag }, buf')
  with
  | Ok v    -> `Ok v
  | Error x -> `Fail (assemble_records (active_protocol_version state.machina) [alert x])

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
