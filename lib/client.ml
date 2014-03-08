open Core
open Flow

let answer_client_hello_params sp ch raw =
  (`Handshaking (sp, [raw]), [`Record (Packet.HANDSHAKE, raw)], `Pass)

let answer_client_hello ch raw =
  let server_name = find_hostname ch in
  let params =
    { entity                = Client ;
      ciphersuite           = List.hd ch.ciphersuites ;
      master_secret         = Cstruct.create 0 ;
      client_random         = ch.random ;
      server_random         = Cstruct.create 0 ;
      dh_params             = None ;
      dh_secret             = None ;
      server_certificate    = None ;
      client_verify_data    = Cstruct.create 0 ;
      server_verify_data    = Cstruct.create 0 ;
      server_name ;
    }
  in
  answer_client_hello_params params ch raw

let answer_server_hello (p : security_parameters) bs sh raw =
  match sh.version with
  | (3, 1) ->
     let verify = Utils.cs_eq (p.client_verify_data <> p.server_verify_data) in
     let rec check_renegotiation = function
       | []                                        -> false
       | (SecureRenegotiation x)::xs when verify x -> true
       | (SecureRenegotiation _)::_                -> false
       | _::xs                                     -> check_renegotiation xs
     in
     (* sends nothing *)
     if check_renegotiation sh.extensions then
       let sp = { p with ciphersuite   = sh.ciphersuites ;
                         server_random = sh.random } in
       (`Handshaking (sp, bs @ [raw]), [], `Pass)
     else
       (`Failure, [`Record (alert Packet.HANDSHAKE_FAILURE)], `Pass)
  | _ -> (`Failure, [`Record (alert Packet.PROTOCOL_VERSION)], `Pass)

let parse_certificates cs =
  let rec getcert acc = function
    | []    -> Some (List.rev acc)
    | c::cs -> match Asn_grammars.certificate_of_cstruct c with
               | None           -> None
               | Some (cert, _) -> getcert (cert :: acc) cs
  in
  getcert [] cs

let answer_certificate p bs cs raw =
  (* sends nothing *)
  match parse_certificates cs with
  | None       ->
     (`Failure, [`Record (alert Packet.BAD_CERTIFICATE)], `Pass)
  | Some []    ->
     (`Failure, [`Record (alert Packet.BAD_CERTIFICATE)], `Pass)
  | Some (x::xs) ->
     let certificates = List.(combine (x::xs) cs) in
     match
       Certificate.verify_certificates ?servername:p.server_name certificates
     with
     | `Fail x ->
        (`Failure, [`Record (alert Packet.BAD_CERTIFICATE)], `Pass)
     | `Ok     ->
        let ps = { p with server_certificate = Some x } in
        (`Handshaking (ps, bs @ [raw]), [], `Pass)

let find_server_rsa_key = function
  | Some x -> Asn_grammars.(match x.tbs_cert.pk_info with
                            | PK.RSA key -> Some key
                            | _          -> None)
  | None   -> None

let find_premaster p =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with
  | Ciphersuite.RSA ->
     let ver = protocol_version_cstruct in
     let premaster = ver <> (default_config.rng 46) in
     ( match find_server_rsa_key p.server_certificate with
       | Some pubkey ->
          let msglen = Cryptokit.RSA.(pubkey.size / 8) in
          Some (Crypto.padPKCS1_and_encryptRSA msglen pubkey premaster, premaster)
       | _           -> None)
  | Ciphersuite.DHE_RSA ->
     (match p.dh_params with
      | Some par ->
         let msg, sec = Crypto.generateDH_secret_and_msg par in
         let shared = Crypto.computeDH par sec par.dh_Ys in
         Some (msg, shared)
      | None -> None)
  | _ -> None


let answer_server_hello_done p bs raw =
  (* sends clientkex change ciper spec; finished *)
  match find_premaster p with
  | Some (kex, premaster) ->
     let ckex = Writer.assemble_handshake (ClientKeyExchange kex) in
     let ccs = Cstruct.create 1 in
     Cstruct.set_uint8 ccs 0 1;
     let client_ctx, server_ctx, params = initialise_crypto_ctx p premaster in
     let to_fin = bs @ [raw; ckex] in
     let checksum = Crypto.finished params.master_secret "client finished" to_fin in
     let fin = Writer.assemble_handshake (Finished checksum) in
     (`KeysExchanged (`Crypted client_ctx, `Crypted server_ctx, { params with client_verify_data = checksum }, to_fin @ [fin]),
      [`Record (Packet.HANDSHAKE, ckex);
       `Record (Packet.CHANGE_CIPHER_SPEC, ccs);
       `Change_enc (`Crypted client_ctx);
       `Record (Packet.HANDSHAKE, fin)],
      `Pass)
  | None                  ->
     (`Failure, [`Record (alert Packet.HANDSHAKE_FAILURE)], `Pass)

let answer_server_key_exchange p bs kex raw =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with
  | Ciphersuite.DHE_RSA ->
     let dh_params, signature, raw_params =
       Reader.parse_dh_parameters_and_signature kex in
     ( match find_server_rsa_key p.server_certificate with
       | Some pubkey ->
          let raw_sig = Crypto.verifyRSA_and_unpadPKCS1 pubkey signature in
          let sigdata = (p.client_random <> p.server_random) <> raw_params in
          let md5 = Crypto.md5 sigdata in
          let sha = Crypto.sha sigdata in
          if (Cstruct.len raw_sig = 36) && (Utils.cs_eq (md5 <> sha) raw_sig) then
            (`Handshaking ( { p with dh_params = Some dh_params }, bs @ [raw]),
             [], `Pass)
          else
            (`Failure, [`Record (alert Packet.HANDSHAKE_FAILURE)], `Pass)
       | None        ->
          (`Failure, [`Record (alert Packet.HANDSHAKE_FAILURE)], `Pass)
     )
  | _ -> (`Failure, [`Record (alert Packet.HANDSHAKE_FAILURE)], `Pass)

let answer_server_finished p bs fin =
  let computed = Crypto.finished p.master_secret "server finished" bs in
  if Utils.cs_eq computed fin then
    (`Established { p with server_verify_data = computed }, [], `Pass)
  else
    (`Failure, [`Record (alert Packet.HANDSHAKE_FAILURE)], `Pass)

let default_client_hello : client_hello =
  { version      = default_config.protocol_version ;
    random       = default_config.rng 32 ;
    sessionid    = None ;
    ciphersuites = default_config.ciphers ;
    extensions   = [] }

let handle_record
    : tls_internal_state -> Packet.content_type -> Cstruct.t
      -> (tls_internal_state * rec_resp list * dec_resp)
 = fun is ct buf ->
    Printf.printf "HANDLE_RECORD (in state %s) %s\n"
                  (state_to_string is)
                  (Packet.content_type_to_string ct);
    match ct with
    | Packet.ALERT ->
       let al = Reader.parse_alert buf in
       Printf.printf "ALERT: %s" (Printer.alert_to_string al);
       (`Failure, [`Record (alert Packet.CLOSE_NOTIFY)], `Pass)
    | Packet.APPLICATION_DATA ->
       Printf.printf "APPLICATION DATA";
       Cstruct.hexdump buf;
       ( match is with
         | `Established _ -> (is, [], `Pass)
         | _ -> (`Failure, [`Record (alert Packet.CLOSE_NOTIFY)], `Pass)
       )
    | Packet.CHANGE_CIPHER_SPEC ->
       (* actually, we're the client and have already sent the kex! *)
       ( match is with
         | `KeysExchanged (_, server_ctx, _, _) ->
            (is, [], `Change_dec server_ctx)
         | _ ->
            (`Failure, [`Record (alert Packet.UNEXPECTED_MESSAGE)], `Pass)
       )
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
         | `Handshaking (p, bs), ServerKeyExchange kex ->
            answer_server_key_exchange p bs kex buf(* sends nothing *)
         | `Handshaking (p, bs), ServerHelloDone ->
            answer_server_hello_done p bs buf
            (* sends clientkex change ciper spec; finished *)
            (* also maybe certificate/certificateverify *)
         | `KeysExchanged (_, _, p, bs), Finished fin ->
              answer_server_finished p bs fin
         | `Established sp, HelloRequest -> (* key renegotiation *)
              let host = match sp.server_name with
                | None   -> []
                | Some x -> [Hostname (Some x)]
              in
              let securereneg = SecureRenegotiation sp.client_verify_data in
              let ch = { default_client_hello with
                         extensions = securereneg :: host } in
              let raw = Writer.assemble_handshake (ClientHello ch) in
              answer_client_hello_params sp ch raw
         | _, _ -> (`Failure, [`Record (alert Packet.HANDSHAKE_FAILURE)], `Pass)
       end
    | _ -> (`Failure, [`Record (alert Packet.UNEXPECTED_MESSAGE)], `Pass)

let handle_tls = handle_tls_int handle_record

let open_connection server =
  let dch = default_client_hello in
  let host = match server with
    | None   -> []
    | Some _ -> [Hostname server]
  in
  let ch = { dch with ciphersuites =
                        dch.ciphersuites @
                          [Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV];
                      extensions   = host
           }
  in
  let buf = Writer.assemble_handshake (ClientHello ch) in
  Writer.assemble_hdr default_config.protocol_version (Packet.HANDSHAKE, buf)
