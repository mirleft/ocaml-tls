open Core
open State

(*
let client_handshake stream =
  let context = empty_client_security_parameters in
  let client_hello, new_context = make_client_hello context in
  send_client_hello stream client_hello context;
  let server_hello, new_context = parse read stream new_context in
  let server_hello_done = parse read stream new_context in
  let client_key_exchange, new_context = make_client_key_exchange new_context in
  send_client_key_exchange stream client_key_exchange context;
  send_change_cipher_spec stream context;
  let connection_state = make_connection_state new_context in
  let context = new_context in
  send_finished stream connection_state;
  connection_state
 *)
module Server = struct
  type server_handshake_state =
    | Initial
    | ServerHelloSent of security_parameters
    | ServerCertificateSent of security_parameters
    | ClientKeyExchangeReceived of security_parameters
    | Finished of security_parameters

  type t = {
    mutable state : server_handshake_state;
    mutable packets : Cstruct.t list;
    mutable outgoing : (int * Cstruct.t) list;
  }

  let make () = { state = Initial ; packets = [] ; outgoing = [] }

  let respond_hello t (ch : client_hello)  =
    let r = Cstruct.create 32 in
    let cipher = Ciphersuite.TLS_RSA_WITH_RC4_128_SHA in
    if List.mem cipher ch.ciphersuites then
      (let kex, enc, hash = Ciphersuite.get_kex_enc_hash cipher in
       let params = { entity = Server ; cipher = enc ; block_or_stream = Block ; mac = hash ; master_secret = Cstruct.create 0 ; client_random = ch.random ; server_random = r } in
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
         (let b = Cstruct.create 200 in
          let buf = Cstruct.shift b 5 in
          Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.CERTIFICATE);
          let cert = [] in (* punch in certs!! *)
          let len = Writer.assemble_certificates (Cstruct.shift buf 4) cert in
          Packet.set_uint24_len (Cstruct.shift buf 1) len;
          let rbuf = Cstruct.sub b 0 (len + 4 + 5) in
          t.state <- ServerCertificateSent params;
          t.outgoing <- (len + 4, rbuf) :: t.outgoing);
(*        if needs_kex kex then
          (let b = Cstruct.create 200 in
           let buf = Cstruct.shift b 5 in
           Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.SERVER_KEY_EXCHANGE);
           let kex = __ in (* punch in cert! *)
           let len = Writer.assemble_certificate (Cstruct.shift buf 4) cert in
           Packet.set_uint24_len (Cstruct.shift buf 1) len;
           let rbuf = Cstruct.sub b 0 (len + 4 + 5) in
           t.state <- ServerCertificateSent params;
           t.outgoing <- (len + 4, rbuf) :: t.outgoing;) *)
       (* server hello done! *)
       let b = Cstruct.create 9 in
       let buf = Cstruct.shift b 5 in
       Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.SERVER_HELLO_DONE);
       Packet.set_uint24_len (Cstruct.shift buf 1) 0;
       t.outgoing <- (4, rbuf) :: t.outgoing)

  let respond_kex t p kex =
    let premastersecret = (* magic decrypt voodoo *) Cstruct.copy kex 0 (Cstruct.len kex) in
    let cr = Cstruct.copy p.client_random 0 32 in
    let sr = Cstruct.copy p.server_random 0 32 in
    let mastersecret = Crypto.generate_master_secret premastersecret (cr ^ sr) in
    let length = 10 (* find and punch in the required length *) in
    let keys = Crypto.key_block length mastersecret (sr ^ cr) in
    (* let ctx = { connection_state instance } in
    <set it up!> *)
    ()

(* let respond_change_cipher_spec =
    security_parameters
    connection_state
    send_change_cipher_spec
    send_finished *)

  let s_to_string t = match t.state with
    | Initial -> "Initial"
    | ServerHelloSent params -> "Server Hello Sent"
    | ServerCertificateSent params -> "Server Certificate Sent"

  let handle_handshake t msg =
    match t.state with
    | Initial -> (match msg with
                  | ClientHello c -> respond_hello t c)
    | ServerCertificateSent p -> (match msg with
                                  | ClientKeyExchange (ClientRsa kex) -> respond_kex t p kex)


  let handle_tls t buf =
    let (header, body), len = Reader.parse buf in
    (* continue parsing if len < Cstruct.len buf!! *)
    match body with
    | TLS_Handshake hs ->
       t.packets <- Cstruct.sub buf 5 len :: t.packets;
       handle_handshake t hs;
       let answers = t.outgoing in
       t.outgoing <- [];
       List.map (fun (l, p) ->
                 t.packets <- Cstruct.shift p 5 :: t.packets;
                 Writer.assemble_hdr p { version = (3, 1) ; content_type = Packet.HANDSHAKE } l;
                 p) answers
(*    | TLS_ChangeCipherSpec -> handle_change_cipher_spec
    | TLS_Alert al -> handle_alert al *)
end



(*
let server_handshake stream =
  let context = empty_server_security_parameters in
  let client_hello, buffer = Reader.parse read stream context in
  TLS_RSA_WITH_3DES_EDE_CBC_SHA
  let server_hello, new_context = make_server_hello context in
  send_server_hello stream server_hello context;
  send_server_certificate stream __ context;
  let new_context =
    if (new_context.cipher needs keyexchange)
      let server_key_exchange, new_context = make_server_key_exchange new_context in
      send_server_key_exchange stream server_key_exchange context;
      new_context
    else
      new_context
  in
  send_server_hello_done stream context;
  let ccs = parse read stream in
  let context = new_context in
  let connection_state = make_connection_state context in
  let finished = parse read stream in
  send_finished stream connection_state;
  connection_state
 *)

let answer_client_hello buf ch =
  let r = Cstruct.create 32 in
  let server_hello = { version = (3, 1); random = r; sessionid = None; ciphersuites =  Ciphersuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA; extensions = [] } in
  Writer.assemble_server_hello buf server_hello

let answer_handshake buf hs =
  let len = match hs with
    | ClientHello ch ->
       Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.SERVER_HELLO);
       answer_client_hello (Cstruct.shift buf 4) ch
    | _ -> assert false
  in
  Packet.set_uint24_len (Cstruct.shift buf 1) len;
  len + 4

let answer req =
  let buf = Cstruct.create 200 in
  let len = match req with
    | TLS_Handshake hs -> answer_handshake (Cstruct.shift buf 5) hs
    | _ -> assert false
  in
  Writer.assemble_hdr buf { version = (3, 1) ; content_type = Packet.HANDSHAKE } len;
  Cstruct.sub buf 0 (len + 5)
