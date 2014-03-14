open Core
open Flow
open Flow.Or_alert

let answer_client_hello_params sp ch raw =
  return (`Handshaking (sp, [raw]), [`Record (Packet.HANDSHAKE, raw)], `Pass)

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
  fail_false (sh.version = default_config.protocol_version) Packet.PROTOCOL_VERSION >>= fun () ->
  let expected = p.client_verify_data <> p.server_verify_data in
  check_reneg expected sh.extensions >>= fun () ->
  let sp = { p with ciphersuite   = sh.ciphersuites ;
                    server_random = sh.random } in
  return (`Handshaking (sp, bs @ [raw]), [], `Pass)

let parse_certificate c =
  match Asn_grammars.certificate_of_cstruct c with
  | None      -> fail Packet.BAD_CERTIFICATE
  | Some cert -> return cert

let answer_certificate p bs cs raw =
  (* sends nothing *)
  mapM parse_certificate cs >>= function
  | []         -> fail Packet.BAD_CERTIFICATE
  | s::_ as xs ->
     let certificates = List.(combine xs cs) in
     Certificate.(
       match
         verify_certificates_debug ?servername:p.server_name certificates
       with
       | `Fail SelfSigned         -> fail Packet.UNKNOWN_CA
       | `Fail NoTrustAnchor      -> fail Packet.UNKNOWN_CA
       | `Fail CertificateExpired -> fail Packet.CERTIFICATE_EXPIRED
       | `Fail _                  -> fail Packet.BAD_CERTIFICATE
       | `Ok                      ->
          let ps = { p with server_certificate = Some s } in
          return (`Handshaking (ps, bs @ [raw]), [], `Pass))

let find_server_rsa_key = function
  | Some x -> Asn_grammars.(match x.tbs_cert.pk_info with
                            | PK.RSA key -> return key
                            | _          -> fail Packet.HANDSHAKE_FAILURE)
  | None   -> fail Packet.HANDSHAKE_FAILURE

let find_premaster p =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with
  | Ciphersuite.RSA ->
     let ver = protocol_version_cstruct in
     let premaster = ver <> (default_config.rng 46) in
     find_server_rsa_key p.server_certificate >>= fun (pubkey) ->
     let msglen = Cryptokit.RSA.(pubkey.size / 8) in
     return (Crypto.padPKCS1_and_encryptRSA msglen pubkey premaster, premaster)
  | Ciphersuite.DHE_RSA ->
     (match p.dh_params with
      | Some par ->
         let msg, sec = Crypto.generateDH_secret_and_msg par in
         let shared = Crypto.computeDH par sec par.dh_Ys in
         return (msg, shared)
      | None -> fail Packet.HANDSHAKE_FAILURE)
  | _ -> fail Packet.HANDSHAKE_FAILURE


let answer_server_hello_done p bs raw =
  (* sends clientkex change ciper spec; finished *)
  find_premaster p >>= fun (kex, premaster) ->
  let ckex = Writer.assemble_handshake (ClientKeyExchange kex) in
  let ccs = Cstruct.create 1 in
  Cstruct.set_uint8 ccs 0 1;
  let client_ctx, server_ctx, p' = initialise_crypto_ctx p premaster in
  let to_fin = bs @ [raw; ckex] in
  let checksum = Crypto.finished p'.master_secret "client finished" to_fin in
  let fin = Writer.assemble_handshake (Finished checksum) in
  let p'' = { p' with client_verify_data = checksum } in
  let ps = to_fin @ [fin] in
  return (`KeysExchanged (`Crypted client_ctx, `Crypted server_ctx, p'', ps),
          [`Record (Packet.HANDSHAKE, ckex);
           `Record (Packet.CHANGE_CIPHER_SPEC, ccs);
           `Change_enc (`Crypted client_ctx);
           `Record (Packet.HANDSHAKE, fin)],
          `Pass)

let answer_server_key_exchange p bs kex raw =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with
  | Ciphersuite.DHE_RSA ->
     let dh_params, signature, raw_params =
       Reader.parse_dh_parameters_and_signature kex in
     find_server_rsa_key p.server_certificate >>= fun (pubkey) ->
     ( match Crypto.verifyRSA_and_unpadPKCS1 pubkey signature with
       | Some raw_sig ->
          let sigdata = (p.client_random <> p.server_random) <> raw_params in
          let md5 = Crypto.md5 sigdata in
          let sha = Crypto.sha sigdata in
          fail_false (Cstruct.len raw_sig = 36) Packet.HANDSHAKE_FAILURE >>= fun () ->
          fail_neq (md5 <> sha) raw_sig Packet.HANDSHAKE_FAILURE >>= fun () ->
          return (`Handshaking ( { p with dh_params = Some dh_params }, bs @ [raw]),
                  [], `Pass)
       | None         -> fail Packet.HANDSHAKE_FAILURE )

  | _ -> fail Packet.UNEXPECTED_MESSAGE

let answer_server_finished p bs fin =
  let computed = Crypto.finished p.master_secret "server finished" bs in
  fail_neq computed fin Packet.HANDSHAKE_FAILURE >>= fun () ->
  return (`Established { p with server_verify_data = computed }, [], `Pass)

let default_client_hello : client_hello =
  { version      = default_config.protocol_version ;
    random       = default_config.rng 32 ;
    sessionid    = None ;
    ciphersuites = default_config.ciphers ;
    extensions   = [] }

let handle_record
    : tls_internal_state -> Packet.content_type -> Cstruct.t
      -> (tls_internal_state * rec_resp list * dec_resp) or_error
 = fun is ct buf ->
    Printf.printf "HANDLE_RECORD (in state %s) %s\n"
                  (state_to_string is)
                  (Packet.content_type_to_string ct);
    match ct with
    | Packet.ALERT ->
       let al = Reader.parse_alert buf in
       Printf.printf "ALERT: %s" (Printer.alert_to_string al);
       return (is, [], `Pass)
    | Packet.APPLICATION_DATA ->
       Printf.printf "APPLICATION DATA";
       Cstruct.hexdump buf;
       ( match is with
         | `Established _ -> return (is, [], `Pass)
         | _              -> fail Packet.UNEXPECTED_MESSAGE
       )
    | Packet.CHANGE_CIPHER_SPEC ->
       (* actually, we're the client and have already sent the kex! *)
       ( match is with
         | `KeysExchanged (_, server_ctx, _, _) ->
            return (is, [], `Change_dec server_ctx)
         | _                                    -> fail Packet.UNEXPECTED_MESSAGE
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
            answer_server_key_exchange p bs kex buf (* sends nothing *)
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
         | _, _ -> fail Packet.HANDSHAKE_FAILURE
       end
    | _ -> fail Packet.UNEXPECTED_MESSAGE

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
