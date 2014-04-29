open Utils

open Core
open Flow
open Flow.Or_alert

open Nocrypto


let answer_client_finished (sp : security_parameters) (packets : Cstruct.t list) (fin : Cstruct.t) (raw : Cstruct.t)  =
  let computed = Crypto.finished sp.protocol_version sp.master_secret "client finished" packets in
  fail_neq computed fin Packet.HANDSHAKE_FAILURE >>= fun () ->
  let my_checksum = Crypto.finished sp.protocol_version sp.master_secret "server finished" (packets @ [raw]) in
  let fin = Writer.assemble_handshake (Finished my_checksum) in
  let params = { sp with client_verify_data = computed ;
                         server_verify_data = my_checksum }
  in
  print_security_parameters params;
  return (`Established, params, [`Record (Packet.HANDSHAKE, fin)], `Pass)

let answer_client_key_exchange (sp : security_parameters) (packets : Cstruct.t list) (kex : Cstruct.t) (raw : Cstruct.t) =
  ( match Ciphersuite.ciphersuite_kex sp.ciphersuite with

    | Ciphersuite.RSA ->
       let private_key = match sp.own_certificate with
          | `Cert_private (_, pk) -> return pk
          | `Cert_none            -> fail Packet.HANDSHAKE_FAILURE in

       (* due to bleichenbacher attach, we should use a random pms *)
       (* then we do not leak any decryption or padding errors! *)
       let other = Writer.assemble_protocol_version sp.protocol_version <+> Rng.generate 46 in
       let validate_premastersecret k =
         (* Client implementations MUST always send the correct version number in
            PreMasterSecret.  If ClientHello.client_version is TLS 1.1 or higher,
            server implementations MUST check the version number as described in
            the note below.  If the version number is TLS 1.0 or earlier, server
            implementations SHOULD check the version number, but MAY have a
            configuration option to disable the check.  Note that if the check
            fails, the PreMasterSecret SHOULD be randomized as described below *)
         match Cstruct.len k == 48,
               Reader.parse_version k,
               sp.protocol_version
         with
         | true, Reader.Or_error.Ok c_ver, TLS_1_0 ->
            if c_ver <= TLS_1_2 then return k else return other
         | true, Reader.Or_error.Ok c_ver, v       ->
            (* here, we need to check c_ver with Client_hello.client_version,
               as described in RFC5246, 7.4.7.1! -- not with protocol_version! *)
            if c_ver = v then return k else return other
         | _, _, _                                 ->
            (* should we have a similar conditional here? *)
            return other
       in
       private_key >>= fun pk ->
          ( match Crypto.decryptRSA_unpadPKCS1 pk kex with
            | None   -> validate_premastersecret other
            | Some k -> validate_premastersecret k )

    | Ciphersuite.DHE_RSA ->
      (* we assume explicit communication here, not a client certificate *)
      ( match sp.dh_state with
        | `Sent (group, secret) -> return @@ DH.shared group secret kex
        | _                     -> fail Packet.HANDSHAKE_FAILURE  )

    | _ -> fail Packet.HANDSHAKE_FAILURE )

  >>= fun premastersecret ->
  let client_ctx, server_ctx, params =
    initialise_crypto_ctx sp premastersecret in
  let ps = packets @ [raw] in
  return (`KeysExchanged (Some server_ctx, Some client_ctx, ps), params, [], `Pass)

let answer_client_hello_params_int sp ch raw =
  let open Packet in

  let random = Rng.generate 32
  and cipher = sp.ciphersuite in

  let server_hello =
    fail_false (List.mem cipher ch.ciphersuites) HANDSHAKE_FAILURE
    >|= fun () ->
    (* now we can provide a certificate with any of the given hostnames *)
    ( match sp.server_name with
      | None   -> ()
      | Some x -> Printf.printf "was asked for hostname %s\n" x );

    let server_hello =
      (* RFC 4366: server shall reply with an empty hostname extension *)
      let host = option [] (fun _ -> [Hostname None]) sp.server_name
      and secren = SecureRenegotiation
        (sp.client_verify_data <+> sp.server_verify_data) in
      { version      = sp.protocol_version ;
        random       = random ;
        sessionid    = None ;
        ciphersuites = cipher ;
        extensions   = secren :: host }
    in
    ( [ Writer.assemble_handshake (ServerHello server_hello) ],
      { sp with server_random = random ; client_random = ch.random } )
  in

  let server_cert params =
    let cert_needed =
      Ciphersuite.(needs_certificate @@ ciphersuite_kex cipher) in
    match (sp.own_certificate, cert_needed) with
    | (`Cert_private (cert, _), true) ->
        let buf =
          [ Writer.assemble_handshake @@
              Certificate [Certificate.cs_of_cert cert] ] in
        return (buf, params)
    | (_, false) -> return ([], params)
    | _          -> fail HANDSHAKE_FAILURE in
    (* ^^^ Rig ciphersuite selection never to end up with one than needs a cert
     * if we haven't got one. *)

  let kex_dhe_rsa params =

    let group         = DH.Group.oakley_2 in (* rfc2409 1024-bit group *)
    let (secret, msg) = DH.gen_secret group in
    let dh_state      = `Sent (group, secret) in
    let written =
      let dh_param = Crypto.dh_params_pack group msg in
      Writer.assemble_dh_parameters dh_param in

    let data = params.client_random <+> params.server_random <+> written in

    let private_key =
      match sp.own_certificate with
      | `Cert_none            -> fail HANDSHAKE_FAILURE
      | `Cert_private (_, pk) -> return pk

    and signature pk =

      let sign x =
        match Crypto.padPKCS1_and_signRSA pk x with
        | None        -> fail HANDSHAKE_FAILURE
        | Some signed -> return signed
      in
      match sp.protocol_version with
      | TLS_1_0 | TLS_1_1 ->
          sign Hash.( MD5.digest data <+> SHA1.digest data )
          >|= Writer.assemble_digitally_signed
      | TLS_1_2 ->
          (* if no signature_algorithms extension is sent by the client,
             support for md5 and sha1 can be safely assumed! *)
        ( match
            map_find ch.extensions ~f:function
              | SignatureAlgorithms xs -> Some xs
              | _                      -> None
          with
          | None    -> return Ciphersuite.SHA
          | Some client_algos ->
              let client_hashes =
                List.(map fst @@ filter (fun (_, x) -> x = RSA) client_algos)
              in
              match List_set.inter client_hashes default_config.hashes with
              | []        -> fail HANDSHAKE_FAILURE
              | hash :: _ -> return hash )
          >>= fun hash ->
            match Crypto.pkcs1_digest_info_to_cstruct hash data with
            | None         -> fail HANDSHAKE_FAILURE
            | Some to_sign ->
                sign to_sign >|= Writer.assemble_digitally_signed_1_2 hash RSA
    in

    private_key >>= signature >|= fun sgn ->
      let kex = written <+> sgn in
      let hs  = Writer.assemble_handshake (ServerKeyExchange kex) in
      ([hs], { params with dh_state }) in

  let kex params =
    let kex = Ciphersuite.ciphersuite_kex cipher in
    if Ciphersuite.(needs_server_kex kex) then
      match kex with
      | Ciphersuite.DHE_RSA -> kex_dhe_rsa params
      | _                   -> return ([], params)
    else return ([], params) in

  server_hello       >>= fun (buf1, params) ->
  server_cert params >>= fun (buf2, params) ->
  kex params         >|= fun (buf3, params) ->
    let buf4 = [ Writer.assemble_handshake ServerHelloDone] in
    let packets = buf1 @ buf2 @ buf3 @ buf4 in
    ( `Handshaking (raw :: packets),
      params,
      List.map (fun e -> `Record (HANDSHAKE, e)) packets,
      `Pass )


let answer_client_hello_params sp ch raw =
  let expected = sp.client_verify_data in
  check_reneg expected ch.extensions >>= fun () ->
  let host = find_hostname ch in
  fail_false (sp.server_name = host) Packet.HANDSHAKE_FAILURE >>= fun () ->
  fail_false (ch.version >= sp.protocol_version) Packet.PROTOCOL_VERSION >>= fun () ->
  answer_client_hello_params_int sp ch raw

let answer_client_hello sp (ch : client_hello) raw =
  fail_false (List.mem Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV ch.ciphersuites) Packet.NO_RENEGOTIATION >>= fun () ->
  let issuported = fun x -> List.mem x ch.ciphersuites in
  fail_false (List.exists issuported default_config.ciphers) Packet.HANDSHAKE_FAILURE >>= fun () ->
  let ciphersuite = List.hd (List.filter issuported default_config.ciphers) in
  let server_name = find_hostname ch in
  ( match supported_protocol_version ch.version with
      | None   -> fail Packet.PROTOCOL_VERSION
      | Some x -> return x ) >>= fun (protocol_version) ->
  let params = { sp with
                   ciphersuite ;
                   protocol_version ;
                   server_name }
  in
  answer_client_hello_params_int params ch raw

let handle_change_cipher_spec sp = function
  | `KeysExchanged (enc, dec, _) as is ->
     let ccs = change_cipher_spec in
     return (is, sp, None, [`Record ccs; `Change_enc enc], `Change_dec dec)
  | _ -> fail Packet.UNEXPECTED_MESSAGE

let handle_handshake sp is buf =
  match Reader.parse_handshake buf with
  | Reader.Or_error.Ok handshake ->
     Printf.printf "HANDSHAKE: %s" (Printer.handshake_to_string handshake);
     Cstruct.hexdump buf;
     ( match (is, handshake) with
       | `Initial, ClientHello ch ->
          answer_client_hello sp ch buf
       | `Handshaking bs, ClientKeyExchange kex ->
          answer_client_key_exchange sp bs kex buf
       | `KeysExchanged (_, _, bs), Finished fin ->
          answer_client_finished sp bs fin buf
       | `Established, ClientHello ch -> (* key renegotiation *)
          answer_client_hello_params sp ch buf
       | _, _-> fail Packet.HANDSHAKE_FAILURE ) >>= fun (sp, is, res, dec) ->
       return (sp, is, None, res, dec)
  | _                           ->
     fail Packet.UNEXPECTED_MESSAGE

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

let new_connection ?cert () = new_state ?cert ()

