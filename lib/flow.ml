open Core


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

let server_handshake stream =
  let context = empty_server_security_parameters in
  let client_hello, new_context = parse read stream context in
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
  let r = Cstruct.create 28 in
  let server_hello = { version = (3, 1); time = ch.time; random = r; sessionid = None; ciphersuites =  Ciphersuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA; extensions = [] } in
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
