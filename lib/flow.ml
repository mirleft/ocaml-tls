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
    | _ -> "something"

  let handle_handshake t msg =
    Printf.printf "handling handshake with state %s\n" (s_to_string t);
    match t.state with
    | Initial -> (match msg with
                  | ClientHello c -> respond_hello t c
                  | _ -> assert false)
    | ServerCertificateSent p -> (match msg with
                                  | ClientKeyExchange (ClientRsa kex) -> respond_kex t p kex
                                  | _ -> assert false)
    | _ -> assert false


  let handle_tls t buf =
    Printf.printf "starting to handle tls\n";
    let (header, body), len = Reader.parse buf in
    (* continue parsing if len < Cstruct.len buf!! *)
    Printf.printf "handle_tls %s\n" (Printer.to_string (header, body));
    match body with
    | TLS_Handshake hs ->
       Printf.printf "calling handling the handshake\n";
       t.packets <- Cstruct.sub buf 5 len :: t.packets;
       handle_handshake t hs;
       let answers = t.outgoing in
       t.outgoing <- [];
       List.rev (List.map (fun (l, p) ->
                           t.packets <- Cstruct.shift p 5 :: t.packets;
                           Writer.assemble_hdr p { version = (3, 1) ; content_type = Packet.HANDSHAKE } l;
                           p)
                          answers)
    | _ -> assert false
(*    | TLS_ChangeCipherSpec -> handle_change_cipher_spec
    | TLS_Alert al -> handle_alert al *)
end
