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
  dh_p               : Cstruct.t option ;
  dh_g               : Cstruct.t option ;
  dh_secret          : Cryptokit.DH.private_secret option ;
  server_certificate : Asn_grammars.certificate option
}

(* EVERYTHING a well-behaved dispatcher needs. And pure, too. *)
type tls_internal_state = [
  | `Initial
  | `Handshaking of security_parameters * Cstruct.t list
  | `KeysExchanged of crypto_state * crypto_state * security_parameters * Cstruct.t list
  | `Established
]

let state_to_string = function
  | `Initial -> "Initial"
  | `Handshaking _ -> "Shaking hands"
  | `KeysExchanged _ -> "Keys are exchanged"
  | `Established -> "Established"


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
       Printf.printf "received mac is"; Cstruct.hexdump mac;
       Printf.printf "computed mac is"; Cstruct.hexdump cmac;
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
