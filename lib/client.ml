open Core
open Flow

let answer_client_hello ch raw =
  let params =
    { entity             = Client ;
      ciphersuite        = List.hd ch.ciphersuites ;
      master_secret      = Cstruct.create 0 ;
      client_random      = ch.random ;
      server_random      = Cstruct.create 0 ;
      dh_p               = None ;
      dh_g               = None ;
      dh_secret          = None ;
      server_certificate = None
    }
  in
  (`Handshaking (params, [raw]), [`Record (Packet.HANDSHAKE, raw)], `Pass)

let answer_server_hello (p : security_parameters) bs sh raw =
  (* sends nothing *)
  let ps = { p with ciphersuite = sh.ciphersuites ; server_random = sh.random } in
  (`Handshaking (ps, bs @ [raw]), [], `Pass)

let answer_certificate p bs cs raw =
  (* sends nothing *)
  let cert = match Asn_grammars.certificate_of_cstruct (List.hd cs) with
    | Some (cert, _) -> cert
    | None -> assert false
  in
  (* TODO: certificate verification *)
  let ps = { p with server_certificate = Some cert } in
  (`Handshaking (ps, bs @ [raw]), [], `Pass)

let answer_server_hello_done p bs raw =
  (* sends clientkex change ciper spec; finished *)
  (* TODO: also maybe certificate/certificateverify *)
  match Ciphersuite.ciphersuite_kex p.ciphersuite with
  | Ciphersuite.RSA ->
     let cert = match p.server_certificate with
       | Some x -> x
       | None -> assert false
     in
     (* TODO: random ;) *)
     let premaster = Cstruct.create 48 in
     Cstruct.set_uint8 premaster 0 3;
     Cstruct.set_uint8 premaster 1 1;
     for i = 2 to 47 do
       Cstruct.set_uint8 premaster i i;
     done;
     let pubkey = Asn_grammars.rsa_public_of_cert cert in
     let msglen = Cryptokit.RSA.(pubkey.size / 8) in
     let kex = Crypto.padPKCS1_and_encryptRSA msglen pubkey premaster in
     let ckex = Writer.assemble_handshake (ClientKeyExchange kex) in
     let ccs = Cstruct.create 1 in
     Cstruct.set_uint8 ccs 0 1;
     let client_ctx, server_ctx, params = initialise_crypto_ctx p premaster in
     let to_fin = bs @ [raw; ckex] in
     let checksum = Crypto.finished params.master_secret "client finished" to_fin in
     let fin = Writer.assemble_handshake (Finished checksum) in
     (`KeysExchanged (`Crypted client_ctx, `Crypted server_ctx, params, to_fin @ [fin]),
      [`Record (Packet.HANDSHAKE, ckex);
       `Record (Packet.CHANGE_CIPHER_SPEC, ccs);
       `Change_enc (`Crypted client_ctx);
       `Record (Packet.HANDSHAKE, fin)],
      `Pass)
  | _ -> assert false

let answer_server_finished p bs fin =
  let computed = Crypto.finished p.master_secret "server finished" bs in
  assert (Utils.cs_eq computed fin);
  (`Established, [], `Pass)

let default_client_hello : client_hello =
  { version      = (3, 1) ;
    random       = Cstruct.create 32 ;
    sessionid    = None ;
    ciphersuites = [Ciphersuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA] ;
    extensions   = [] }

let handle_record
    : tls_internal_state -> content_type -> Cstruct.t
      -> (tls_internal_state * rec_resp list * dec_resp)
 = fun is ct buf ->
    Printf.printf "HANDLE_RECORD (in state %s) %s\n"
                  (state_to_string is)
                  (Packet.content_type_to_string ct);
    match ct with
    | Packet.ALERT ->
       let al = Reader.parse_alert buf in
       Printf.printf "ALERT: %s" (Printer.alert_to_string al);
       (is, [], `Pass)
    | Packet.APPLICATION_DATA ->
       Printf.printf "APPLICATION DATA";
       Cstruct.hexdump buf;
       (is, [], `Pass)
    | Packet.CHANGE_CIPHER_SPEC ->
       (* actually, we're the client and have already sent the kex! *)
       begin
         match is with
         | `KeysExchanged (_, server_ctx, _, _) ->
              (is, [], `Change_dec server_ctx)
         | _ -> assert false
       end
    | Packet.HANDSHAKE ->
       begin
         let handshake = Reader.parse_handshake buf in
         Printf.printf "HANDSHAKE: %s" (Printer.handshake_to_string handshake);
         Cstruct.hexdump buf;
         match (is, handshake) with
          (* this initiates a connection --
             we use the pipeline with a manually crafted ClientHello *)
         | `Initial, ClientHello ch ->
            answer_client_hello ch buf
         | `Handshaking (p, bs), ServerHello sh ->
            answer_server_hello p bs sh buf (* sends nothing *)
         | `Handshaking (p, bs), Certificate cs ->
            answer_certificate p bs cs buf (* sends nothing *)
(*         | `Handshaking (p, bs), ServerKeyExchange kex ->
            answer_server_key_exchange p bs kex buf(* sends nothing *) *)
         | `Handshaking (p, bs), ServerHelloDone ->
            answer_server_hello_done p bs buf
            (* sends clientkex change ciper spec; finished *)
            (* also maybe certificate/certificateverify *)
         | `KeysExchanged (_, _, p, bs), Finished fin ->
              answer_server_finished p bs fin
         | `Established, HelloRequest -> (* key renegotiation *)
              let ch = default_client_hello in
              answer_client_hello ch buf
         | _, _-> assert false
       end
    | _ -> assert false

let handle_tls = handle_tls_int handle_record

let open_connection =
  let ch = default_client_hello in
  let buf = Writer.assemble_handshake (ClientHello ch) in
  Writer.assemble_hdr (Packet.HANDSHAKE, buf)
