open Nocrypto

open Utils

open Core
open State
open Handshake_common
open Config

let (<+>) = Cs.(<+>)

let answer_client_finished state master_secret fin raw log =
  let client_computed =
    Handshake_crypto.finished state.version master_secret "client finished" log in
  guard (Cs.equal client_computed fin) Packet.HANDSHAKE_FAILURE >>= fun () ->

  let server_checksum = Handshake_crypto.finished state.version master_secret "server finished" (log @ [raw]) in
  let fin = Writer.assemble_handshake (Finished server_checksum) in

  let rekeying = Some (client_computed, server_checksum) in
  let machina = Server ServerEstablished in

  return ({ state with machina ; rekeying }, [`Record (Packet.HANDSHAKE, fin)], `Pass)

let establish_master_secret state params premastersecret raw log =
  let client_ctx, server_ctx, master_secret =
    Handshake_crypto.initialise_crypto_ctx state.version params premastersecret in
  let machina = ClientKeyExchangeReceived (server_ctx, client_ctx, master_secret, log @ [raw]) in
  return ({ state with machina = Server machina }, [], `Pass)

let answer_client_key_exchange_RSA state params kex raw log =
  let private_key config = match config.own_certificate with
    | Some (_, priv) -> return priv
    | None           -> fail Packet.HANDSHAKE_FAILURE
  in

  (* due to bleichenbacher attach, we should use a random pms *)
  (* then we do not leak any decryption or padding errors! *)
  let other = Writer.assemble_protocol_version state.version <+> Rng.generate 46 in
  let validate_premastersecret k =
    (* Client implementations MUST always send the correct version number in
       PreMasterSecret.  If ClientHello.client_version is TLS 1.1 or higher,
       server implementations MUST check the version number as described in
       the note below.  If the version number is TLS 1.0 or earlier, server
       implementations SHOULD check the version number, but MAY have a
       configuration option to disable the check.  Note that if the check
       fails, the PreMasterSecret SHOULD be randomized as described below *)
    match Cstruct.len k == 48, Reader.parse_version k with
    | true, Reader.Or_error.Ok c_ver when c_ver = params.client_version -> return k
    | _ -> return other
  in

  private_key state.config >>= fun priv ->
  ( match Crypto.decryptRSA_unpadPKCS1 priv kex with
    | None   -> validate_premastersecret other
    | Some k -> validate_premastersecret k ) >>= fun pms ->
  establish_master_secret state params pms raw log

let answer_client_key_exchange_DHE_RSA state params (group, secret) kex raw log =
  let pms = DH.shared group secret kex in
  establish_master_secret state params pms raw log

let answer_client_hello_params state params ch raw =
  let open Packet in

  let cipher = params.cipher in

  let server_hello client_hello rekeying version random =
    (* we could provide a certificate with any of the given hostnames *)
    (* TODO: preserve this hostname somewhere maybe? *)
    let server_name = find_hostname client_hello in

    let server_hello =
      (* RFC 4366: server shall reply with an empty hostname extension *)
      let host = option [] (fun _ -> [Hostname None]) server_name
      and secren =
        match rekeying with
        | None            -> SecureRenegotiation (Cstruct.create 0)
        | Some (cvd, svd) -> SecureRenegotiation (cvd <+> svd)
      in
      { version      = version ;
        random       = random ;
        sessionid    = None ;
        ciphersuites = cipher ;
        extensions   = secren :: host }
    in
    Writer.assemble_handshake (ServerHello server_hello)
  in

  let server_cert config params =
    let cert_needed =
      Ciphersuite.(needs_certificate @@ ciphersuite_kex cipher) in
    match config.own_certificate, cert_needed with
    | Some (cert, _), true ->
        return [ Writer.assemble_handshake @@ Certificate [Certificate.cs_of_cert cert] ]
    | _, false -> return []
    | _        -> fail HANDSHAKE_FAILURE in
    (* ^^^ Rig ciphersuite selection never to end up with one than needs a cert
     * if we haven't got one. *)

  let kex_dhe_rsa config params version client_hello =
    let group         = DH.Group.oakley_2 in (* rfc2409 1024-bit group *)
    let (secret, msg) = DH.gen_secret group in
    let dh_state      = group, secret in
    let written =
      let dh_param = Crypto.dh_params_pack group msg in
      Writer.assemble_dh_parameters dh_param in

    let data = params.client_random <+> params.server_random <+> written in

    let private_key =
      match config.own_certificate with
      | None         -> fail HANDSHAKE_FAILURE
      | Some (_, pk) -> return pk

    and signature pk =

      let sign x =
        match Crypto.padPKCS1_and_signRSA pk x with
        | None        -> fail HANDSHAKE_FAILURE
        | Some signed -> return signed
      in
      match version with
      | TLS_1_0 | TLS_1_1 ->
          sign Hash.( MD5.digest data <+> SHA1.digest data )
          >|= Writer.assemble_digitally_signed
      | TLS_1_2 ->
          (* if no signature_algorithms extension is sent by the client,
             support for md5 and sha1 can be safely assumed! *)
        ( match
            map_find client_hello.extensions ~f:function
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
      (hs, dh_state) in

  let sh = server_hello ch state.rekeying state.version params.server_random in
  server_cert state.config params >>= fun certificates ->

  let hello_done = Writer.assemble_handshake ServerHelloDone in

  ( match Ciphersuite.ciphersuite_kex cipher with
    | Ciphersuite.DHE_RSA ->
       kex_dhe_rsa state.config params state.version ch >>= fun (kex, dh) ->
       let outs = sh :: certificates @ [ kex ; hello_done] in
       let machina = ServerHelloDoneSent_DHE_RSA (params, dh, raw :: outs) in
       return (outs, machina)
  | Ciphersuite.RSA ->
     let outs = sh :: certificates @ [ hello_done] in
     let machina = ServerHelloDoneSent_RSA (params, raw :: outs) in
     return (outs, machina)
  ) >|= fun (out_recs, machina) ->

  ({ state with machina = Server machina },
   List.map (fun e -> `Record (HANDSHAKE, e)) out_recs,
   `Pass)


let answer_client_hello state (ch : client_hello) raw =
  let find_version requested config =
    match supported_protocol_version config requested with
    | Some x -> return x
    | None   -> fail Packet.PROTOCOL_VERSION

  and find_ciphersuite requested server_supported =
    match List_set.inter server_supported requested with
    | []   -> fail Packet.HANDSHAKE_FAILURE
    | c::_ -> return c

  and ensure_reneg rekeying ciphers exts =
    match rekeying, List.mem Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV ciphers with
    | None, true         -> return ()
    | None, false        -> check_reneg (Cstruct.create 0) exts
    | Some (cvd, _), _   -> check_reneg cvd exts

  (* if we're asked to rekey, make sure the config says so as well *)
  and really_rekey rekeying rekey =
    match rekeying, rekey with
    | Some _, false -> fail Packet.HANDSHAKE_FAILURE
    | _ , _         -> return ()
  in

  really_rekey state.rekeying state.config.use_rekeying >>= fun () ->
  find_version ch.version state.config >>= fun version ->
  find_ciphersuite ch.ciphersuites state.config.ciphers >>= fun cipher ->
  ensure_reneg state.rekeying ch.ciphersuites ch.extensions >>= fun () ->

  let params =
    { server_random = Rng.generate 32 ;
      client_random = ch.random ;
      client_version = ch.version ;
      cipher = cipher }
  in
  let hs = { state with version } in
  answer_client_hello_params hs params ch raw

let handle_change_cipher_spec ss state packet =
  (* TODO: validate packet is good (ie parse it?) *)
  match ss with
  | ClientKeyExchangeReceived (server_ctx, client_ctx, master_secret, log) ->
     let ccs = change_cipher_spec in
     let machina = ClientChangeCipherSpecReceived (master_secret, log) in
     return ({ state with machina = Server machina },
             [`Record ccs; `Change_enc (Some server_ctx)],
             `Change_dec (Some client_ctx))
  | _ ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_handshake ss hs buf =
  let open Reader in
  match parse_handshake buf with
  | Or_error.Ok handshake ->
     Printf.printf "HANDSHAKE: %s" (Printer.handshake_to_string handshake);
     Cstruct.hexdump buf;
     ( match ss, handshake with
       | ServerInitial, ClientHello ch ->
          answer_client_hello hs ch buf
       | ServerHelloDoneSent_RSA (params, log), ClientKeyExchange kex ->
          answer_client_key_exchange_RSA hs params kex buf log
       | ServerHelloDoneSent_DHE_RSA (params, dh_sent, log), ClientKeyExchange kex ->
          answer_client_key_exchange_DHE_RSA hs params dh_sent kex buf log
       | ClientChangeCipherSpecReceived (master_secret, log), Finished fin ->
          answer_client_finished hs master_secret fin buf log
       | ServerEstablished, ClientHello ch -> (* rekeying *)
          answer_client_hello hs ch buf
       | _, _-> fail Packet.HANDSHAKE_FAILURE )
  | Or_error.Error _ -> fail Packet.UNEXPECTED_MESSAGE
