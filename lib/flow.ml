open Core

module Or_alert =
  Control.Or_error_make (struct type err = Packet.alert_type end)
open Or_alert

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
}

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

let empty_state = { machina   = `Initial ;
                    decryptor = `Nothing ;
                    encryptor = `Nothing ;
                    fragment  = Cstruct.create 0
                  }

(* some config parameters *)
type config = {
  ciphers          : Ciphersuite.ciphersuite list ;
  rng              : int -> Cstruct.t ;
  protocol_version : int * int
}

let default_config = {
  ciphers          = Ciphersuite.([TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ;
                                   TLS_RSA_WITH_3DES_EDE_CBC_SHA ;
                                   TLS_RSA_WITH_RC4_128_SHA ;
                                   TLS_RSA_WITH_RC4_128_MD5]) ;
  rng              = (fun n -> Cstruct.create n) ; (* TODO: better random *)
  protocol_version = (3, 1)
}

let protocol_version_cstruct =
  let buf = Cstruct.create 2 in
  let major, minor = default_config.protocol_version in
  Cstruct.set_uint8 buf 0 major;
  Cstruct.set_uint8 buf 1 minor;
  buf

(* well-behaved pure encryptor *)
let encrypt : crypto_state -> Packet.content_type -> Cstruct.t -> crypto_state * Cstruct.t
= fun s ty buf ->
    match s with
    | `Nothing -> (s, buf)
    | `Crypted ctx ->
       let sign = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty default_config.protocol_version buf in
       let to_encrypt = buf <> sign in
       let enc, next_iv =
         match ctx.stream_cipher with
         | Some x -> (Crypto.crypt_stream x to_encrypt, Cstruct.create 0)
         | None -> Crypto.encrypt_block ctx.cipher ctx.cipher_secret ctx.cipher_iv to_encrypt
       in
       (`Crypted { ctx with sequence = Int64.succ ctx.sequence ;
                            cipher_iv = next_iv },
        enc)

let fail_false v err =
  match v with
  | true ->  return ()
  | false -> fail err

let fail_neq cs1 cs2 err =
  fail_false (Utils.cs_eq cs1 cs2) err

(* well-behaved pure decryptor *)
let decrypt : crypto_state -> Packet.content_type -> Cstruct.t -> (crypto_state * Cstruct.t) or_error
= fun s ty buf ->
    match s with
    | `Nothing -> return (s, buf)
    | `Crypted ctx ->
       let dec, next_iv =
         match ctx.stream_cipher with
         | Some x -> (Crypto.crypt_stream x buf, Cstruct.create 0)
         | None   -> Crypto.decrypt_block ctx.cipher ctx.cipher_secret ctx.cipher_iv buf
       in
       let macstart = (Cstruct.len dec) - (Ciphersuite.hash_length ctx.mac) in
       let body, mac = Cstruct.split dec macstart in
       let cmac = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty default_config.protocol_version body in
       fail_neq cmac mac Packet.DECRYPTION_FAILED >>= fun () ->
       return (`Crypted { ctx with sequence = Int64.succ ctx.sequence ;
                                   cipher_iv = next_iv },
               body)

(* party time *)
let rec separate_records : Cstruct.t ->  ((tls_hdr * Cstruct.t) list * Cstruct.t)
= fun buf ->
  match Cstruct.len buf with
  | 0             -> ([], buf)
  | x when x <= 5 -> ([], buf)
  | x             ->
     match Reader.parse_hdr buf with
     | (_, buf', len) when len > (Cstruct.len buf') -> ([], buf)
     | (hdr, buf', len)                             ->
        let tl, frag = separate_records (Cstruct.shift buf' len) in
        ((hdr, (Cstruct.sub buf' 0 len)) :: tl, frag)

let assemble_records : record list -> Cstruct.t =
  o Utils.cs_appends @@ List.map @@ (Writer.assemble_hdr default_config.protocol_version)

type rec_resp = [
  | `Change_enc of crypto_state
  | `Record     of record
]
type dec_resp = [ `Change_dec of crypto_state | `Pass ]

let initialise_crypto_ctx : security_parameters -> Cstruct.t -> (crypto_context * crypto_context * security_parameters)
 = fun sp premastersecret ->
     let mastersecret = Crypto.generate_master_secret premastersecret (sp.client_random <> sp.server_random) in
     Printf.printf "master secret\n";
     Cstruct.hexdump mastersecret;

     let key, iv, mac = Ciphersuite.ciphersuite_cipher_mac_length sp.ciphersuite in
     let keyblocklength =  2 * key + 2 * mac + 2 * iv in
     let keyblock = Crypto.key_block keyblocklength mastersecret (sp.server_random <> sp.client_random) in

     let c_mac, off = (Cstruct.sub keyblock 0 mac, mac) in
     let s_mac, off = (Cstruct.sub keyblock off mac, off + mac) in
     let c_key, off = (Cstruct.sub keyblock off key, off + key) in
     let s_key, off = (Cstruct.sub keyblock off key, off + key) in
     let c_iv, off = (Cstruct.sub keyblock off iv, off + iv) in
     let s_iv = Cstruct.sub keyblock off iv in

     let mac = Ciphersuite.ciphersuite_mac sp.ciphersuite in
     let sequence = 0L in
     let cipher = Ciphersuite.ciphersuite_cipher sp.ciphersuite in

     let c_stream_cipher, s_stream_cipher =
       match cipher with
       | Ciphersuite.RC4_128 ->
          let ccipher = new Cryptokit.Stream.arcfour (Cstruct.copy c_key 0 key) in
          let scipher = new Cryptokit.Stream.arcfour (Cstruct.copy s_key 0 key) in
          (Some ccipher, Some scipher)
       | _ -> (None, None)
     in

     let c_context =
       { stream_cipher = c_stream_cipher ;
         cipher_secret = c_key ;
         cipher_iv = c_iv ;
         mac_secret = c_mac ;
         cipher ; mac ; sequence } in
     let s_context =
       { stream_cipher = s_stream_cipher ;
         cipher_secret = s_key ;
         cipher_iv = s_iv ;
         mac_secret = s_mac ;
         cipher ; mac ; sequence } in
     (c_context, s_context, { sp with master_secret = mastersecret })

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
  return ({ machina ; encryptor ; decryptor ; fragment = state.fragment }, encs)

let alert typ =
  let buf = Writer.assemble_alert typ in
  (Packet.ALERT, buf)

type ret = [
  | `Ok of (state * Cstruct.t)
  | `Fail of Cstruct.t
]

let handle_tls_int : (tls_internal_state -> Packet.content_type -> Cstruct.t
      -> (tls_internal_state * rec_resp list * dec_resp) or_error) ->
                 state -> Cstruct.t -> ret
= fun handler state buf ->
  match
    let in_records, frag = separate_records (state.fragment <> buf) in
    foldM (fun (st, raw_rs) r ->
           map (fun (st', raw_rs') -> (st', raw_rs @ raw_rs')) @@
             handle_raw_record handler st r)
          (state, [])
          in_records
    >>= fun (state', out_records) ->
    let buf' = assemble_records out_records in
    Printf.printf "sending out"; Cstruct.hexdump buf';
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
