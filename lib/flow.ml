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

module Server = struct
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
end
