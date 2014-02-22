open Core

let ref _ = raise (Failure "no.")

let o f g x = f (g x)

module Server = struct
  (*
   * MORNING PRAYER:
   *
   * I will allocate data, more and more data and all new data, since i'm not
   * writing C like a peasant.
   *
   * This kinda travesty will go away. After we reach correctness. Not before.
   *)

  let cs_appends csn =
    let cs =
      Cstruct.create @@
        List.fold_left (fun x cs -> x + Cstruct.len cs) 0 csn in
    let _ =
      List.fold_left
        (fun off e ->
          let len = Cstruct.len e in
          ( Cstruct.blit e 0 cs off len ; off + len ))
        0 csn in
    cs

  let cs_append cs1 cs2 = cs_appends [ cs1; cs2 ]


  type content_type = Packet.content_type

  type stream_crypto_context = {
    sequence      : int64 ;
    cipher        : Cryptokit.Stream.stream_cipher ; (* XXX *)
    mac           : Ciphersuite.hash_algorithm ;
    mac_secret    : string
  }

  (* EVERYTHING a cipher needs, be it input or output. And pure, too. *)
  type crypto_state = [
    `Nothing
  | `Stream of stream_crypto_context
(*  | `Block of int64 * block_encryption_algorithm * string * hash_algorithm *)
  ]

  type handshake_state =
    | ServerHelloSent
    | ClientKeyExchangeReceived of crypto_state * crypto_state
    | Established

  type connection_end = Server | Client

  type security_parameters = {
    entity              : connection_end;
    cipher              : Ciphersuite.encryption_algorithm;
    mac                 : Ciphersuite.hash_algorithm;
    master_secret       : string;
    client_random       : Cstruct.t;
    server_random       : Cstruct.t
  }

  (* EVERYTHING a well-behaved dispatcher needs. And pure, too. *)
  type tls_internal_state = [
      `Initial
    | `Handshaking of handshake_state * security_parameters * Cstruct.t list
    | `Established
  ]

  let state_to_string = function
    | `Initial -> "Initial"
    | `Handshaking x -> "Shaking hands"
    | `Established -> "Established"

  let answer_client_finished (is : tls_internal_state) (hs : handshake_state) (sp : security_parameters) (packets : Cstruct.t list) (buf : Cstruct.t) (raw : Cstruct.t)  =
    let msgs = Cstruct.copyv packets in
    let computed = Crypto.finished sp.master_secret "client finished" msgs in
    let checksum = Cstruct.copy buf 0 12 in
    assert (computed = checksum);
    let my_check = Crypto.finished sp.master_secret "server finished" (msgs ^ Cstruct.copy raw 0 (Cstruct.len raw)) in
    let send = Writer.assemble_handshake (Finished (Cstruct.of_string my_check)) in
    (is, [`Record (Packet.HANDSHAKE, send)], `Pass)


  let answer_client_key_exchange (is : tls_internal_state) (hs : handshake_state) (sp : security_parameters) (packets : Cstruct.t list) (kex : Cstruct.t) (raw : Cstruct.t) =
    let len = Cstruct.BE.get_uint16 kex 0 in
    let pms = Crypto.decryptRSA (Crypto_utils.get_key "server.key") (Cstruct.copy kex 2 len) in
    let premastersecret = String.sub pms ((String.length pms) - 48) 48 in
    let cr = Cstruct.copy sp.client_random 0 32 in
    let sr = Cstruct.copy sp.server_random 0 32 in
    let mastersecret = Crypto.generate_master_secret premastersecret (cr ^ sr) in
    Printf.printf "master secret\n";
    Cstruct.hexdump (Cstruct.of_string mastersecret);
    let keylen, ivlen, _ = Ciphersuite.key_lengths sp.cipher in
    let hashlen = Ciphersuite.hash_length sp.mac in
    let length =  2 * keylen + 2 * hashlen (* + 2 * ivlen *) in
    let keyblock = Crypto.key_block length mastersecret (sr ^ cr) in

    let client_mac_key   = String.sub keyblock 0                      hashlen in
    let server_mac_key   = String.sub keyblock hashlen                hashlen in
    let client_write_key = String.sub keyblock (2 * hashlen)          keylen in
    let server_write_key = String.sub keyblock (2 * hashlen + keylen) keylen in

    let ccipher = new Cryptokit.Stream.arcfour client_write_key in
    let scipher = new Cryptokit.Stream.arcfour server_write_key in


    let client_crypto_context = `Stream { sequence      = Int64.of_int 0 ;
                                          cipher        = ccipher ;
                                          mac           = sp.mac ;
                                          mac_secret    = client_mac_key }
    in
    let server_crypto_context = `Stream { sequence       = Int64.of_int 0 ;
                                          cipher         = scipher ;
                                          mac            = sp.mac ;
                                          mac_secret     = server_mac_key }
    in
    let params = { entity        = sp.entity ;
                   cipher        = sp.cipher ;
                   mac           = sp.mac ;
                   master_secret = mastersecret ;
                   client_random = sp.client_random ;
                   server_random = sp.server_random }
    in
    let handshake_state = ClientKeyExchangeReceived (server_crypto_context, client_crypto_context) in
    (`Handshaking (handshake_state, params, packets @ [raw]), [], `Pass)

  let answer_client_hello (ch : client_hello) raw =
    let cipher = Ciphersuite.TLS_RSA_WITH_RC4_128_SHA in
    assert (List.mem cipher ch.ciphersuites);
    let kex, enc, hash = Ciphersuite.get_kex_enc_hash cipher in
    (* TODO : real random *)
    let r = Cstruct.create 32 in
    let params = { entity        = Server ;
                   cipher        = enc ;
                   mac           = hash ;
                   master_secret = "" ;
                   client_random = ch.random ;
                   server_random = r } in
    let server_hello : server_hello = { version      = (3, 1) ;
                                        random       = r ;
                                        sessionid    = None ;
                                        ciphersuites = cipher ;
                                        extensions   = [] } in
    let bufs = [Writer.assemble_handshake (ServerHello server_hello)] in
    let bufs' =
      if Ciphersuite.needs_certificate kex then
        (let cert = Crypto_utils.get_cert_from_file "server.pem" in
         bufs @ [Writer.assemble_handshake (Certificate [cert])])
      else
        bufs
    in
    (* TODO: Server Key Exchange *)
    (* server hello done! *)
    let hello_done = Writer.assemble_handshake ServerHelloDone in
    let packets = bufs' @ [hello_done] in
    (`Handshaking (ServerHelloSent, params, raw :: packets),
     List.map (fun e -> `Record (Packet.HANDSHAKE, e)) packets,
     `Pass)

  type record = content_type * Cstruct.t

  (* this is the externally-visible state somebody will keep track of for us. *)
  type state = {
    machina   : tls_internal_state ;
    decryptor : crypto_state ;
    encryptor : crypto_state ;
  }

  let empty_state = { machina = `Initial ; decryptor = `Nothing ; encryptor = `Nothing }


  (* well-behaved pure encryptor *)
  let encrypt : crypto_state -> content_type -> Cstruct.t -> crypto_state * Cstruct.t
  = fun s ty buf ->
      match s with
      | `Nothing -> (s, buf)
      | `Stream ctx ->
         let data = Cstruct.copy buf 0 (Cstruct.len buf) in
         let sign = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty data in
         let enc = Crypto.crypt_stream ctx.cipher (data ^ sign) in
         let add1 = Int64.add (Int64.of_int 1) in
         (`Stream { ctx with sequence = add1 ctx.sequence },
          Cstruct.of_string enc)

  (* well-behaved pure decryptor *)
  let decrypt : crypto_state -> content_type -> Cstruct.t -> crypto_state * Cstruct.t
  = fun s ty buf ->
      match s with
      | `Nothing -> (s, buf)
      | `Stream ctx ->
         let data = Cstruct.copy buf 0 (Cstruct.len buf) in
         let dec = Crypto.crypt_stream ctx.cipher data in
         Printf.printf "decrypted\n";
         Cstruct.hexdump (Cstruct.of_string dec);
         let maclength = Ciphersuite.hash_length ctx.mac in
         let macstart = (String.length dec) - maclength in
         let body = String.sub dec 0 macstart in
         let mac = String.sub dec macstart maclength in
         let cmac = Crypto.signature ctx.mac ctx.mac_secret ctx.sequence ty body in
         assert (cmac = mac);
         let add1 = Int64.add (Int64.of_int 1) in
         (`Stream { ctx with sequence = add1 ctx.sequence },
          Cstruct.of_string body)

  (* party time *)
  let rec separate_records : Cstruct.t ->  (tls_hdr * Cstruct.t) list
  = fun buf -> (* we assume no fragmentation here *)
    match Cstruct.len buf with
    | 0 -> []
    | _ ->
      let (hdr, buf', len) = Reader.parse_hdr buf in
      (hdr, buf') :: separate_records (Cstruct.shift buf len)

  let assemble_records : record list -> Cstruct.t =
    o cs_appends @@ List.map @@ Writer.assemble_hdr

  type rec_resp = [
    | `Change_enc of crypto_state
    | `Record     of record
  ]
  type dec_resp = [ `Change_dec of crypto_state | `Pass ]

  let handle_record
  : tls_internal_state -> content_type -> Cstruct.t
    -> (tls_internal_state * rec_resp list * dec_resp)
  = fun is ct buf ->
    Printf.printf "HANDLE_RECORD (in state %s) %s\n"
                  (state_to_string is)
                  (Packet.content_type_to_string ct);
    match (is, ct) with
    | _, Packet.ALERT ->
       let al = Reader.parse_alert buf in
       Printf.printf "ALERT: %s" (Printer.alert_to_string al);
       (is, [], `Pass)
    | _, Packet.APPLICATION_DATA ->
       Printf.printf "APPLICATION DATA";
       Cstruct.hexdump buf;
       (is, [], `Pass)
    | `Initial, Packet.HANDSHAKE ->
       (match Reader.parse_handshake buf with
        | ClientHello ch -> answer_client_hello ch buf
        | _ -> assert false)
    | `Handshaking (hs, sp, packets), Packet.HANDSHAKE ->
       (match Reader.parse_handshake buf with
        | ClientKeyExchange (ClientRsa kex) -> answer_client_key_exchange is hs sp packets kex buf
        | Finished fin -> answer_client_finished is hs sp packets fin buf
        | _ -> assert false
       )
    | `Handshaking (hs, sp, _), Packet.CHANGE_CIPHER_SPEC ->
       (match hs with
        | ClientKeyExchangeReceived (enc, dec) ->
           let ccs = Cstruct.create 1 in
           Cstruct.set_uint8 ccs 0 1;
           (is, (* maybe we need to add the raw packet? *)
            [`Record (Packet.CHANGE_CIPHER_SPEC, ccs); `Change_enc enc],
            `Change_dec dec)
        | _ -> assert false)
    | _, _ -> assert false

  let handle_raw_record state (hdr, buf) =
    let (dec_st, dec) = decrypt state.decryptor hdr.content_type buf in
    let (machina, items, dec_cmd) =
      handle_record state.machina hdr.content_type dec in
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

  let handle_tls : state -> Cstruct.t -> state * Cstruct.t
  = fun state buf ->
    let in_records = separate_records buf in
    let (state', out_records) =
      let rec loop st = function
        | []    -> (st, [])
        | r::rs ->
            let (st1, raw_rs ) = handle_raw_record st r in
            let (st2, raw_rs') = loop st1 rs in
            (st2, raw_rs @ raw_rs') in
      loop state in_records in
    let buf' = assemble_records out_records in
    (state', buf')

end
