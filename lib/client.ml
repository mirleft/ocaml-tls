open Core
open Flow
open Flow.Or_alert

open Nocrypto

let answer_client_hello_params sp ch raw =
  return (`Handshaking (sp, [raw]), None, [`Record (Packet.HANDSHAKE, raw)], `Pass)

let answer_client_hello ch raw =
  let server_name = find_hostname ch in
  let params =
    { entity                = Client ;
      ciphersuite           = List.hd ch.ciphersuites ;
      master_secret         = Cstruct.create 0 ;
      client_random         = ch.random ;
      server_random         = Cstruct.create 0 ;
      dh_state              = `Initial ;
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
  return (`Handshaking (sp, bs @ [raw]), None, [], `Pass)

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
          return (`Handshaking (ps, bs @ [raw]), None, [], `Pass))

let find_server_rsa_key = function
  | Some x -> Asn_grammars.(match x.tbs_cert.pk_info with
                            | PK.RSA key -> return key
                            | _          -> fail Packet.HANDSHAKE_FAILURE)
  | None   -> fail Packet.HANDSHAKE_FAILURE

let find_premaster p =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with

  | Ciphersuite.RSA ->
     let ver = protocol_version_cstruct in
     let premaster = ver <> Rng.generate 46 in
     find_server_rsa_key p.server_certificate
     >>= fun pubkey ->
     return (Crypto.padPKCS1_and_encryptRSA pubkey premaster, premaster)

  | Ciphersuite.DHE_RSA ->
    ( match p.dh_state with
      | `Received (group, s_secret) ->
          let (secret, msg) = DH.gen_secret group in
          let shared        = DH.shared group secret s_secret in
          return (msg, shared)
      | _ -> fail Packet.HANDSHAKE_FAILURE )

  | _ -> fail Packet.HANDSHAKE_FAILURE


let answer_server_hello_done p bs raw =
  (* sends clientkex change ciper spec; finished *)
  find_premaster p >>= fun (kex, premaster) ->
  let ckex = Writer.assemble_handshake (ClientKeyExchange kex) in
  let ccs = change_cipher_spec in
  let client_ctx, server_ctx, p' = initialize_crypto_ctx p premaster in
  let to_fin = bs @ [raw; ckex] in
  let checksum = Crypto.finished p'.master_secret "client finished" to_fin in
  let fin = Writer.assemble_handshake (Finished checksum) in
  let p'' = { p' with client_verify_data = checksum } in
  let ps = to_fin @ [fin]
  in
  return (`KeysExchanged (Some client_ctx, Some server_ctx, p'', ps),
          None,
          [`Record (Packet.HANDSHAKE, ckex);
           `Record ccs;
           `Change_enc (Some client_ctx);
           `Record (Packet.HANDSHAKE, fin)],
          `Pass)

let answer_server_key_exchange p bs kex raw =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with
  | Ciphersuite.DHE_RSA ->
    ( match Reader.parse_dh_parameters_and_signature kex with
      | Reader.Or_error.Ok (dh_params, signature, raw_params) ->
          let dh_state = `Received (Crypto.dh_params_unpack dh_params) in
          find_server_rsa_key p.server_certificate
          >>= fun pubkey ->
          ( match Crypto.verifyRSA_and_unpadPKCS1 pubkey signature with
            | Some raw_sig ->
                let sigdata = p.client_random <> p.server_random <> raw_params in
                let sig_ = Hash.( MD5.digest sigdata <> SHA1.digest sigdata ) in
                fail_false (Cstruct.len raw_sig = 36) Packet.HANDSHAKE_FAILURE >>= fun () ->
                fail_neq sig_ raw_sig Packet.HANDSHAKE_FAILURE >>= fun () ->
                return (`Handshaking ({ p with dh_state }, bs @ [raw]), None, [], `Pass)
            | None -> fail Packet.HANDSHAKE_FAILURE )
       | _ -> fail Packet.HANDSHAKE_FAILURE )

  | _ -> fail Packet.UNEXPECTED_MESSAGE

let answer_server_finished p bs fin =
  let computed = Crypto.finished p.master_secret "server finished" bs in
  fail_neq computed fin Packet.HANDSHAKE_FAILURE >>= fun () ->
  print_security_parameters p;
  return (`Established { p with server_verify_data = computed }, None, [], `Pass)

let default_client_hello : client_hello =
  { version      = default_config.protocol_version ;
    random       = Rng.generate 32 ;
    sessionid    = None ;
    ciphersuites = default_config.ciphers ;
    extensions   = [] }

let handle_change_cipher_spec = function
  (* actually, we're the client and have already sent the kex! *)
  | `KeysExchanged (_, server_ctx, _, _) as is ->
     return (is, None, [], `Change_dec server_ctx)
  | _                                    ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_handshake is buf =
  match Reader.parse_handshake buf with
  | Reader.Or_error.Ok handshake ->
     Printf.printf "HANDSHAKE: %s" (Printer.handshake_to_string handshake);
     Cstruct.hexdump buf;
     ( match (is, handshake) with
       (* we use the pipeline with a manually crafted ClientHello to initiate the connection*)
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
       | _, _ -> fail Packet.HANDSHAKE_FAILURE )
  | _ -> fail Packet.UNEXPECTED_MESSAGE

let handle_record
    : tls_internal_state -> Packet.content_type -> Cstruct.t
      -> (tls_internal_state * Cstruct.t option * rec_resp list * dec_resp) or_error
 = fun is ct buf ->
    Printf.printf "HANDLE_RECORD (in state %s) %s\n"
                  (state_to_string is)
                  (Packet.content_type_to_string ct);
    match ct with
    | Packet.ALERT -> handle_alert buf
    | Packet.APPLICATION_DATA ->
       Printf.printf "APPLICATION DATA";
       Cstruct.hexdump buf;
       ( match is with
         | `Established _ -> return (is, Some buf, [], `Pass)
         | _              -> fail Packet.UNEXPECTED_MESSAGE
       )
    | Packet.CHANGE_CIPHER_SPEC -> handle_change_cipher_spec is
    | Packet.HANDSHAKE -> handle_handshake is buf

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
