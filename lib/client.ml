open Core
open Flow
open Flow.Or_alert

open Nocrypto

let answer_server_hello (p : security_parameters) bs sh raw =
  (match supported_protocol_version sh.version with
     | None   -> fail Packet.PROTOCOL_VERSION
     | Some x -> return { p with protocol_version = x } ) >>= fun (sp) ->
  let expected = sp.client_verify_data <> sp.server_verify_data in
  check_reneg expected sh.extensions >>= fun () ->
  let sp' = { sp with
                ciphersuite   = sh.ciphersuites ;
                server_random = sh.random } in
  return (`Handshaking (bs @ [raw]), sp', [], `Pass)

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
          let sp = { p with server_certificate = Some s } in
          return (`Handshaking (bs @ [raw]), sp, [], `Pass))

let find_server_rsa_key = function
  | Some x -> Asn_grammars.(match x.tbs_cert.pk_info with
                            | PK.RSA key -> return key
                            | _          -> fail Packet.HANDSHAKE_FAILURE)
  | None   -> fail Packet.HANDSHAKE_FAILURE

let find_premaster p =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with

  | Ciphersuite.RSA ->
     let ver = Writer.assemble_protocol_version p.protocol_version in
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
  return (`KeysExchanged (Some client_ctx, Some server_ctx, ps),
          p'',
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
                return (`Handshaking (bs @ [raw]), { p with dh_state }, [], `Pass)
            | None -> fail Packet.HANDSHAKE_FAILURE )
       | _ -> fail Packet.HANDSHAKE_FAILURE )

  | _ -> fail Packet.UNEXPECTED_MESSAGE

let answer_server_finished p bs fin =
  let computed = Crypto.finished p.master_secret "server finished" bs in
  fail_neq computed fin Packet.HANDSHAKE_FAILURE >>= fun () ->
  print_security_parameters p;
  return (`Established, { p with server_verify_data = computed }, [], `Pass)

let default_client_hello () =
  { version      = max_protocol_version ;
    random       = Rng.generate 32 ;
    sessionid    = None ;
    ciphersuites = default_config.ciphers ;
    extensions   = [] }

let answer_hello_request sp =
  let host = match sp.server_name with
    | None   -> []
    | Some x -> [Hostname (Some x)]
  in
  let securereneg = SecureRenegotiation sp.client_verify_data in
  let ch = { default_client_hello () with
               extensions = securereneg :: host } in
  let raw = Writer.assemble_handshake (ClientHello ch) in
  return (`Handshaking [raw], sp, [`Record (Packet.HANDSHAKE, raw)], `Pass)

let handle_change_cipher_spec sp = function
  (* actually, we're the client and have already sent the kex! *)
  | `KeysExchanged (_, server_ctx, _) as is ->
     return (is, sp, None, [], `Change_dec server_ctx)
  | _                                    ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_handshake sp is buf =
  match Reader.parse_handshake buf with
  | Reader.Or_error.Ok handshake ->
     Printf.printf "HANDSHAKE: %s" (Printer.handshake_to_string handshake);
     Cstruct.hexdump buf;
     ( match (is, handshake) with
       | `Handshaking bs, ServerHello sh ->
          answer_server_hello sp bs sh buf
       | `Handshaking bs, Certificate cs ->
          answer_certificate sp bs cs buf
       | `Handshaking bs, ServerKeyExchange kex ->
          answer_server_key_exchange sp bs kex buf
       | `Handshaking bs, ServerHelloDone ->
          answer_server_hello_done sp bs buf
       | `KeysExchanged (_, _, bs), Finished fin ->
          answer_server_finished sp bs fin
       | `Established, HelloRequest ->
          answer_hello_request sp
       | _, _ -> fail Packet.HANDSHAKE_FAILURE ) >>= fun (is, sp, res, dec) ->
       return (is, sp, None, res, dec)
  | _ -> fail Packet.UNEXPECTED_MESSAGE

let handle_record
    : tls_internal_state -> security_parameters -> Packet.content_type -> Cstruct.t
      -> (tls_internal_state * security_parameters * Cstruct.t option * rec_resp list * dec_resp) or_error
 = fun is sp ct buf ->
    Printf.printf "HANDLE_RECORD (in state %s) %s\n"
                  (state_to_string is)
                  (Packet.content_type_to_string ct);
    match ct with
    | Packet.ALERT -> handle_alert sp buf
    | Packet.APPLICATION_DATA ->
       ( match is with
         | `Established -> return (is, sp, Some buf, [], `Pass)
         | _            -> fail Packet.UNEXPECTED_MESSAGE
       )
    | Packet.CHANGE_CIPHER_SPEC -> handle_change_cipher_spec sp is
    | Packet.HANDSHAKE -> handle_handshake sp is buf

let handle_tls = handle_tls_int handle_record

let new_connection server =
  let state = empty_state in
  let host = match server with
    | None   -> []
    | Some _ -> [Hostname server]
  in
  let client_hello =
    let dch = default_client_hello () in
      { dch with
          ciphersuites = dch.ciphersuites @ [Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV];
          extensions   = host
      }
  in
  let security_parameters =
    { state.security_parameters with
        client_random = client_hello.random ;
        server_name   = server ;
    }
  in
  let raw = Writer.assemble_handshake (ClientHello client_hello) in
  let machina = `Handshaking [raw] in
  send_records
      { state with security_parameters ; machina }
      [(Packet.HANDSHAKE, raw)]
