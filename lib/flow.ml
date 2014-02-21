open Core
open State

(*

let handle : tls_state -> Cstruct.t
          -> (tls_state * (* out *) Cstruct.t * (* rest? *) Cstruct.t)

let send : tls_state -> Cstruct.t -> (tls_state * Cstruct.t)

let handle_io : tls_state -> Cstruct.t
             -> (tls_state * (* rest? *) Cstruct.t) Lwt.t

let send_io : tls_state -> Cstruct.t -> tls_state Lwt.t

*)

let ref _ = raise (Failure "no.")

let o f g x = f (g x)

module Server = struct
(*

  type server_handshake_state =
    | Initial
    | ServerHelloSent of security_parameters
    | ServerCertificateSent of security_parameters
    | ClientKeyExchangeReceived of security_parameters
    | Established

  type t = {
    mutable state : server_handshake_state;
    mutable packets : string list;
    mutable outgoing : (int * Cstruct.t) list;
    mutable ctx : connection_state ;
    mutable next_ctx : connection_state option ;
  }

  let make () = { state = Initial ;
                  packets = [] ;
                  outgoing = [] ;
                  ctx = empty_ctx ;
                  next_ctx = None }


  let respond_hello t (ch : client_hello)  =
      let r = Cstruct.create 32 in
      let cipher = Ciphersuite.TLS_RSA_WITH_RC4_128_SHA in
      if List.mem cipher ch.ciphersuites then
        (let kex, enc, hash = Ciphersuite.get_kex_enc_hash cipher in
        let params = { entity = Server ; cipher = enc ; block_or_stream = Block ; mac = hash ; master_secret = "" ; client_random = ch.random ; server_random = r } in
        let b = Cstruct.create 200 in
        let buf = Cstruct.shift b 5 in
        Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.SERVER_HELLO);
        let server_hello : server_hello = { version = (3, 1) ; random = r ; sessionid = None ; ciphersuites = cipher ; extensions = [] } in
        let len = Writer.assemble_server_hello (Cstruct.shift buf 4) server_hello in
        Packet.set_uint24_len (Cstruct.shift buf 1) len;
        let rbuf = Cstruct.sub b 0 (len + 4 + 5) in
        t.state <- ServerHelloSent params;
        t.outgoing <- (len + 4, rbuf) :: t.outgoing;
        if Ciphersuite.needs_certificate kex then
          (let b = Cstruct.create 1000 in
            let buf = Cstruct.shift b 5 in
            Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.CERTIFICATE);
            let cert = Crypto_utils.get_cert_from_file "server.pem" in
            let len = Writer.assemble_certificates (Cstruct.shift buf 4) [cert] in
            Packet.set_uint24_len (Cstruct.shift buf 1) len;
            let rbuf = Cstruct.sub b 0 (len + 4 + 5) in
            t.state <- ServerCertificateSent params;
            t.outgoing <- (len + 4, rbuf) :: t.outgoing);
        (* TODO: Server Key Exchange *)
        (* server hello done! *)
        let b = Cstruct.create 9 in
        let buf = Cstruct.shift b 5 in
        Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.SERVER_HELLO_DONE);
        Packet.set_uint24_len (Cstruct.shift buf 1) 0;
        t.outgoing <- (4, b) :: t.outgoing)



  let respond_kex t p kex =
    Printf.printf "respond_kex\n";
    Printf.printf "before premastersecret (kex len %d)\n" (Cstruct.len kex);
    let len = Cstruct.BE.get_uint16 kex 0 in
    let pms = Crypto_utils.decrypt (Cstruct.copy kex 2 len) in
    let premastersecret = String.sub pms ((String.length pms) - 48) 48 in
    Printf.printf "premastersecret is %s\n" premastersecret;
    Cstruct.hexdump (Cstruct.of_string premastersecret);
    let cr = Cstruct.copy p.client_random 0 32 in
    let sr = Cstruct.copy p.server_random 0 32 in
    Printf.printf "client random\n";
    Cstruct.hexdump (Cstruct.of_string cr);
    Printf.printf "server random\n";
    Cstruct.hexdump (Cstruct.of_string sr);
    let mastersecret = Crypto.generate_master_secret premastersecret (cr ^ sr) in
    Printf.printf "master secret %s\n" mastersecret;
    Cstruct.hexdump (Cstruct.of_string mastersecret);
    let key, iv, blocksize = key_lengths p.cipher in
    let hash, passing = hash_length_padding p.mac in
    let length =  2 * key + 2 * hash (* + 2 * iv *) in
    let keyblock = Crypto.key_block length mastersecret (sr ^ cr) in
    let cs =
      { sequence_number = 0 ;
        client_write_MAC_secret = String.sub keyblock 0 hash ;
        server_write_MAC_secret = String.sub keyblock hash hash ;
        client_write_key = String.sub keyblock (2 * hash) key ;
        server_write_key = String.sub keyblock (2 * hash + key) key}
    in
    t.next_ctx <- Some cs;
    let params = { entity = p.entity ;
                   cipher = p.cipher ;
                   block_or_stream = p.block_or_stream ;
                   mac = p.mac ;
                   master_secret = mastersecret ;
                   client_random = p.client_random ;
                   server_random = p.server_random }
    in
    t.state <- ClientKeyExchangeReceived params

  let handle_change_cipher_spec t =
    let Some ct = t.next_ctx in
    t.ctx <- ct;
    t.next_ctx <- None;
    let buf = Cstruct.create 6 in
    Cstruct.set_uint8 buf 5 1;
    (buf, 1)

  let respond_finished t p buf =
    let should = Crypto.finished p.master_secret "client finished" (String.concat "" t.packets) in
    let is = Cstruct.copy buf 0 12 in
    if should = is then
      Printf.printf "success!! respond finished successfully"
    else
      Printf.printf "failure!! respond finished unsuccessfully"

  let s_to_string t = match t.state with
    | Initial -> "Initial"
    | ServerHelloSent params -> "Server Hello Sent"
    | ServerCertificateSent params -> "Server Certificate Sent"
    | ClientKeyExchangeReceived params -> "Client Key Exchange Received"
    | Established -> "Connection Established"

  let handle_handshake t msg =
    Printf.printf "handling handshake with state %s\n" (s_to_string t);
    match t.state with
    | Initial -> (match msg with
                  | ClientHello c -> respond_hello t c
                  | _ -> assert false)
    | ServerCertificateSent p -> (match msg with
                                  | ClientKeyExchange (ClientRsa kex) -> respond_kex t p kex
                                  | _ -> assert false)
    | ClientKeyExchangeReceived p -> (match msg with
                                      | Finished buf -> respond_finished t p buf
                                      | _ -> assert false)
    | _ -> assert false


  let decrypt t buf =
    if (String.length t.ctx.client_write_key) <> 0 then
      let transform = Cryptokit.Cipher.(arcfour t.ctx.client_write_key Encrypt) in
      let dec = Cryptokit.transform_string transform (Cstruct.copy buf 0 (Cstruct.len buf)) in
      let mybuf = Cstruct.of_string dec in
      Printf.printf "decrypted message!!\n";
      Cstruct.hexdump mybuf;
      mybuf
    else
      buf

  let hexdump ~msg cs =
    Printf.printf "%s\n%!" msg;
    Cstruct.hexdump cs


  let handle_tls t buf =
    Printf.printf "starting to handle tls\n";
    Cstruct.hexdump buf;
    let header, bbuf, len = Reader.parse_hdr buf in
    let bodybuf = decrypt t bbuf in
    Printf.printf "parsing decrypted body\n";
    Cstruct.hexdump bodybuf;
    let body = Reader.parse_body header.content_type bodybuf in
    Printf.printf "parsed body\n";
    Printf.printf "handle_tls (len %d, buflen %d) %s\n" len (Cstruct.len buf) (Printer.to_string (header, body));
    let ans = match body with
    | TLS_Handshake hs ->
       Printf.printf "calling handling the handshake\n";
       t.packets <- Cstruct.copy buf 5 (len - 5) :: t.packets;
       handle_handshake t hs;
       let answers = t.outgoing in
       t.outgoing <- [];
       List.rev (List.map (fun (l, p) ->
                           t.packets <- Cstruct.copy p 5 l :: t.packets;
                           Writer.assemble_hdr p { version = (3, 1) ; content_type = Packet.HANDSHAKE } l;
                           p)
                          answers)
    | TLS_ChangeCipherSpec ->
       let p, len = handle_change_cipher_spec t in
       Writer.assemble_hdr p { version = (3, 1) ; content_type = Packet.CHANGE_CIPHER_SPEC } len;
       [p]
    (* | TLS_Alert al -> handle_alert al *)
    in
    (ans, len)

 *)



  (* new core handler *)


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

  (* this should have been defined somewhere around here? *)
  type content_type = Packet.content_type

  (* EVERYTHING a well-behaved dispatcher needs. And pure, too. *)
  type tls_internal_state = unit

  type stream_encryption_algorithm = Cryptokit.transform
  type hash_algorithm = Cryptokit.hash

  (* EVERYTHING a cipher needs, be it input or output. And pure, too. *)
  type crypto_state = [
    `Nothing
  | `Stream of int64 * stream_encryption_algorithm * hash_algorithm
(*  | `Block of int * encryption_algorithm * string * string * hash_algorithm * string *)
  ]

  type record = content_type * Cstruct.t

  (* this is the externally-visible state somebody will keep track of for us. *)
  type state = {
    machina   : tls_internal_state ;
    decryptor : crypto_state ;
    encryptor : crypto_state ;
  }

  let signature : hash_algorithm -> int64 -> content_type -> string -> string
    = fun mac n ty data ->
            let dlen = String.length data in
            let prefix = Cstruct.create 9 in
            Cstruct.BE.set_uint64 prefix 0 n;
            Cstruct.set_uint8 prefix 4 (Packet.content_type_to_int ty);
            Cstruct.set_uint8 prefix 5 3; (* version major *)
            Cstruct.set_uint8 prefix 6 1; (* version minor *)
            Cstruct.BE.set_uint16 prefix 7 dlen;
            let ps = Cstruct.copy prefix 0 9 in
            Cryptokit.hash_string mac (ps ^ data)

  (* well-behaved pure encryptor *)
  let encrypt_ : crypto_state -> Cstruct.t -> crypto_state * Cstruct.t
  = fun s buf -> match s with
                 | `Nothing -> (s, buf)
                 | `Stream (seq, cipher, mac) ->
                    let data = Cstruct.copy buf 0 (Cstruct.len buf) in
                    (* TODO : needs type!!! *)
                    let sign = signature mac seq Packet.HANDSHAKE data in
                    let enc = Cryptokit.transform_string cipher (data ^ sign) in
                    (`Stream ((Int64.add seq (Int64.of_int 1)), cipher, mac),
                     Cstruct.of_string enc)

  (* well-behaved pure decryptor *)
  let decrypt_ : crypto_state -> Cstruct.t -> crypto_state * Cstruct.t
  = fun s buf -> match s with
                 | `Nothing -> (s, buf)
                 | `Stream (seq, cipher, mac) ->
                    let data = Cstruct.copy buf 0 (Cstruct.len buf) in
                    let dec = Cryptokit.transform_string cipher data in
                    let declength = String.length dec in
                    let maclength = 20 (* TODO: mac.mac_length *) in
                    let macstart = declength - maclength in
                    let body = String.sub dec 0 macstart in
                    let actual_signature = String.sub dec macstart maclength in
                    (* TODO: real content_type *)
                    let computed_signature = signature mac seq Packet.HANDSHAKE body in
                    assert (actual_signature = computed_signature);
                    (`Stream ((Int64.add seq (Int64.of_int 1)), cipher, mac),
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
      `Change_enc of crypto_state
    | `Record     of record
  ]
  type dec_resp = [ `Change_dec of crypto_state | `Pass ]

  let handle_record
  : tls_internal_state -> tls_hdr -> Cstruct.t
    -> (tls_internal_state * rec_resp list * dec_resp)
  = fun _ -> assert false

  let handle_raw_record state (hdr, buf) =
    let (dec_st, dec) = decrypt_ state.decryptor buf in
    let (machina, items, dec_cmd) =
      handle_record state.machina hdr dec in
    let (encryptor, encs) =
      let rec loop st = function
        | [] -> (st, [])
        | `Change_enc st'   :: xs -> loop st' xs
        | `Record (ty, buf) :: xs ->
            let (st1, enc ) = encrypt_ st buf in
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
