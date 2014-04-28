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


(* sends nothing *)
let answer_certificate p bs cs raw =
  let open Certificate in

  let parse css =
    match parse_stack css with
    | None       -> fail Packet.BAD_CERTIFICATE
    | Some stack -> return stack

  and validate ((server, _) as stack) =
    match
      X509.Validator.validate p.validator ?host:p.server_name stack
    with
    | `Fail SelfSigned         -> fail Packet.UNKNOWN_CA
    | `Fail NoTrustAnchor      -> fail Packet.UNKNOWN_CA
    | `Fail CertificateExpired -> fail Packet.CERTIFICATE_EXPIRED
    | `Fail _                  -> fail Packet.BAD_CERTIFICATE
    | `Ok                      ->
        let sp = { p with peer_certificate = `Cert_public server } in
        (* due to triple-handshake (https://secure-resumption.com) we better
          ensure that we got the same certificate *)
        (* match p.server_certificate with
        | Some x when x = s ->
          return (`Handshaking (bs @ [raw]), sp, [], `Pass)
        | Some _            ->
          fail Packet.HANDSHAKE_FAILURE
        | None              -> *)
        return (`Handshaking (bs @ [raw]), sp, [], `Pass)
  in
  parse cs >>= validate

let peer_rsa_key = function
  | `Cert_public cert ->
      let open Asn_grammars in
      ( match Certificate.(asn_of_cert cert).tbs_cert.pk_info with
        | PK.RSA key -> return key
        | _          -> fail Packet.HANDSHAKE_FAILURE )
  | `Cert_unknown -> fail Packet.HANDSHAKE_FAILURE

let find_premaster p =
  match Ciphersuite.ciphersuite_kex p.ciphersuite with

  | Ciphersuite.RSA ->
     let ver = Writer.assemble_protocol_version p.protocol_version in
     let premaster = ver <> Rng.generate 46 in
     peer_rsa_key p.peer_certificate >>= fun pubkey ->
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
  let client_ctx, server_ctx, p' = initialise_crypto_ctx p premaster in
  let to_fin = bs @ [raw; ckex] in
  let checksum = Crypto.finished p.protocol_version p'.master_secret "client finished" to_fin in
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
  let open Packet in
  match Ciphersuite.ciphersuite_kex p.ciphersuite with
  | Ciphersuite.DHE_RSA ->
     peer_rsa_key p.peer_certificate >>= fun pubkey ->
     ( match Reader.parse_dh_parameters kex with
       | Reader.Or_error.Ok (dh_params, raw_params, rest) ->
          let dh_state = `Received (Crypto.dh_params_unpack dh_params) in
          ( match p.protocol_version with
            | TLS_1_0 | TLS_1_1 ->
               ( match Reader.parse_digitally_signed rest with
                 | Reader.Or_error.Ok signature ->
                    let cm should data =
                      let csig = Hash.( MD5.digest data <> SHA1.digest data) in
                      fail_neq should csig HANDSHAKE_FAILURE
                    in
                    return (signature, cm)
                 | _ -> fail UNEXPECTED_MESSAGE )
            | TLS_1_2 ->
               match Reader.parse_digitally_signed_1_2 rest with
               | Reader.Or_error.Ok (hasha, RSA, signature) ->
                   let cmp should to_hash =
                     match Crypto.pkcs1_digest_info_of_cstruct should with
                     | Some (hasha', target) when hasha = hasha' ->
                        if Crypto.hash_eq hasha ~target to_hash then
                          return ()
                        else fail HANDSHAKE_FAILURE
                     | _ -> fail UNEXPECTED_MESSAGE
                   in
                   return (signature, cmp)
               | _ -> fail UNEXPECTED_MESSAGE )
          >>= fun (signature, csig) ->
          ( match Crypto.verifyRSA_and_unpadPKCS1 pubkey signature with
            | Some raw_sig ->
               let sigdata = p.client_random <> p.server_random <> raw_params in
               csig raw_sig sigdata >>= fun () ->
               return (`Handshaking (bs @ [raw]), { p with dh_state }, [], `Pass)
            | None -> fail HANDSHAKE_FAILURE )
       | _ -> fail HANDSHAKE_FAILURE )

  | _ -> fail UNEXPECTED_MESSAGE

let answer_server_finished p bs fin =
  let computed = Crypto.finished p.protocol_version p.master_secret "server finished" bs in
  fail_neq computed fin Packet.HANDSHAKE_FAILURE >>= fun () ->
  print_security_parameters p;
  return (`Established, { p with server_verify_data = computed }, [], `Pass)

let default_client_hello () =
  let version = max_protocol_version in
  let extensions = match version with
    | TLS_1_0 | TLS_1_1 -> []
    | TLS_1_2 ->
       let supported = List.map (fun h -> (h, Packet.RSA)) default_config.hashes in
       [SignatureAlgorithms supported]
  in
  { version ;
    random       = Rng.generate 32 ;
    sessionid    = None ;
    ciphersuites = default_config.ciphers ;
    extensions }

let answer_hello_request sp =
  let host = match sp.server_name with
    | None   -> []
    | Some x -> [Hostname (Some x)]
  in
  let securereneg = SecureRenegotiation sp.client_verify_data in
  let dch = default_client_hello () in
  let ch = { dch with
               extensions = securereneg :: host @ dch.extensions } in
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

let new_connection ?cert ?host:server ~validator () =
  let state = new_state ?cert () in
  let host = match server with
    | None   -> []
    | Some _ -> [Hostname server]
  in
  let client_hello =
    let dch = default_client_hello () in
      { dch with
          ciphersuites = dch.ciphersuites @ [Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV];
          extensions   = host @ dch.extensions
      }
  in
  let security_parameters =
    { state.security_parameters with
        client_random = client_hello.random ;
        server_name   = server ;
        validator
    }
  in
  let raw = Writer.assemble_handshake (ClientHello client_hello) in
  let machina = `Handshaking [raw] in
  send_records
      { state with security_parameters ; machina }
      [(Packet.HANDSHAKE, raw)]
