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
    | ServerHelloSent of Cstruct.t * security_parameters
    | ServerCertificateSent of Cstruct.t * security_parameters
    | ClientKeyExchangeReceived of Cstruct.t * security_parameters

  type t = {
    mutable state : server_handshake_state
  }

  let make () = { state = Initial }

  let respond t client_hello =
    let r = Cstruct.create 32 in
    let params = { entity = Server ; cipher = Ciphersuite.TRIPLE_DES_EDE_CBC ; block_or_stream = Block ; mac = Ciphersuite.SHA ; master_secret = Cstruct.create 0 ; client_random = client_hello.random ; server_random = r } in
    let b = Cstruct.create 200 in
    let buf = Cstruct.shift b 5 in
    Cstruct.set_uint8 buf 0 (Packet.handshake_type_to_int Packet.SERVER_HELLO);
    let server_hello = { version = (3, 1) ; random = r ; sessionid = None ; ciphersuites = Ciphersuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA ; extensions = [] } in
    let len = Writer.assemble_server_hello (Cstruct.shift buf 4) server_hello in
    Packet.set_uint24_len (Cstruct.shift buf 1) len;
    let rbuf = Cstruct.sub b 0 (len + 4 + 5) in
    t.state <- ServerHelloSent (Cstruct.sub buf 0 (len + 4), params);
    (len + 4, rbuf)

  let s_to_string t = match t.state with
    | Initial -> "Initial"
    | ServerHelloSent (buf, params) -> "Server Hello Sent"

  let handle_handshake t msg =
    match t.state with
    | Initial -> match msg with
                 | ClientHello c -> respond t c


  let handle_tls t buf =
    let (header, body), len = Reader.parse buf in
    (* continue parsing if len < Cstruct.len buf!! *)
    match body with
    | TLS_Handshake hs ->
       let len, resbuf = handle_handshake t hs in
       Writer.assemble_hdr resbuf { version = (3, 1) ; content_type = Packet.HANDSHAKE } len;
       Cstruct.sub resbuf 0 (len + 5)
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
