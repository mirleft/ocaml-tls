open Core

let ref _ = raise (Failure "no.")

let o f g x = f (g x)

let (<>) = Utils.cs_append

type content_type = Packet.content_type

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
  entity             : connection_end ;
  ciphersuite        : Ciphersuite.ciphersuite ;
  master_secret      : Cstruct.t ;
  client_random      : Cstruct.t ;
  server_random      : Cstruct.t ;
  dh_params          : dh_parameters option ;
  dh_secret          : Cryptokit.DH.private_secret option ;
  server_certificate : Asn_grammars.certificate option ;
  client_verify_data : Cstruct.t ;
  server_verify_data : Cstruct.t ;
}

(* EVERYTHING a well-behaved dispatcher needs. And pure, too. *)
type tls_internal_state = [
  | `Initial
  | `Handshaking of security_parameters * Cstruct.t list
  | `KeysExchanged of crypto_state * crypto_state * security_parameters * Cstruct.t list (* only used in server, client initiates change cipher spec *)
  | `Established of security_parameters
]

let state_to_string = function
  | `Initial -> "Initial"
  | `Handshaking _ -> "Shaking hands"
  | `KeysExchanged _ -> "Keys are exchanged"
  | `Established _ -> "Established"


type record = content_type * Cstruct.t

(* this is the externally-visible state somebody will keep track of for us. *)
type state = {
  machina   : tls_internal_state ;
  decryptor : crypto_state ;
  encryptor : crypto_state ;
}

let empty_state = { machina = `Initial ;
                    decryptor = `Nothing ;
                    encryptor = `Nothing }


(* well-behaved pure encryptor *)
let encrypt : crypto_state -> content_type -> Cstruct.t -> crypto_state * Cstruct.t
= fun s ty buf ->
    match s with
    | `Nothing -> (s, buf)
    | `Crypted ctx ->
       let sign = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty buf in
       let to_encrypt = buf <> sign in
       let enc, next_iv =
         match ctx.stream_cipher with
         | Some x -> (Crypto.crypt_stream x to_encrypt, Cstruct.create 0)
         | None -> Crypto.encrypt_block ctx.cipher ctx.cipher_secret ctx.cipher_iv to_encrypt
       in
       (`Crypted { ctx with sequence = Int64.succ ctx.sequence ;
                            cipher_iv = next_iv },
        enc)

(* well-behaved pure decryptor *)
let decrypt : crypto_state -> content_type -> Cstruct.t -> crypto_state * Cstruct.t
= fun s ty buf ->
    match s with
    | `Nothing -> (s, buf)
    | `Crypted ctx ->
       let dec, next_iv =
         match ctx.stream_cipher with
         | Some x -> (Crypto.crypt_stream x buf, Cstruct.create 0)
         | None -> Crypto.decrypt_block ctx.cipher ctx.cipher_secret ctx.cipher_iv buf
       in
       let macstart = (Cstruct.len dec) - (Ciphersuite.hash_length ctx.mac) in
       let body, mac = Cstruct.split dec macstart in
       let cmac = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty body in
       assert (Utils.cs_eq cmac mac);
       (`Crypted { ctx with sequence = Int64.succ ctx.sequence ;
                            cipher_iv = next_iv },
        body)

(* party time *)
let rec separate_records : Cstruct.t ->  (tls_hdr * Cstruct.t) list
= fun buf -> (* we assume no fragmentation here *)
  match Cstruct.len buf with
  | 0 -> []
  | _ ->
    let (hdr, buf', len) = Reader.parse_hdr buf in
    (hdr, buf') :: separate_records (Cstruct.shift buf len)

let assemble_records : record list -> Cstruct.t =
  o Utils.cs_appends @@ List.map @@ Writer.assemble_hdr

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
  let (dec_st, dec) = decrypt state.decryptor hdr.content_type buf in
  let (machina, items, dec_cmd) =
    handler state.machina hdr.content_type dec in
  let (encryptor, encs) =
    let rec loop st = function
      | [] -> (st, [])
      | `Change_enc st'   :: xs -> loop st' xs
      | `Record (ty, buf) :: xs ->
          let (st1, enc ) = encrypt st ty buf in
          let (st2, rest) = loop st1 xs in
          (st2, (ty, enc) :: rest)
    in
    loop state.encryptor items in
  let decryptor = match dec_cmd with
    | `Change_dec dec -> dec
    | `Pass           -> dec_st in
  ({ machina ; encryptor ; decryptor }, encs)

let handle_tls_int : (tls_internal_state -> content_type -> Cstruct.t
      -> (tls_internal_state * rec_resp list * dec_resp)) ->
                 state -> Cstruct.t -> state * Cstruct.t
= fun handler state buf ->
  let in_records = separate_records buf in
  let (state', out_records) =
    let rec loop st = function
      | []    -> (st, [])
      | r::rs ->
          let (st1, raw_rs ) = handle_raw_record handler st r in
          let (st2, raw_rs') = loop st1 rs in
          (st2, raw_rs @ raw_rs') in
    loop state in_records in
  let buf' = assemble_records out_records in
  (state', buf')
