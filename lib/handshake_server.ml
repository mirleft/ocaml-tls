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
  assure (Cs.equal client_computed fin)
  >>= fun () ->
  let server_checksum
    = Handshake_crypto.finished state.version master_secret "server finished" (log @ [raw]) in
  let fin = Finished server_checksum in
  let fin_raw = Writer.assemble_handshake fin in
  assure (Cs.null state.hs_fragment)
  >|= fun () ->
  let reneg = Some (client_computed, server_checksum) in
  let machina = Server Established
  in
  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake fin ;
  ({ state with machina ; reneg }, [`Record (Packet.HANDSHAKE, fin_raw)])

let establish_master_secret state params premastersecret raw log =
  let client_ctx, server_ctx, master_secret =
    Handshake_crypto.initialise_crypto_ctx state.version params premastersecret in
  let machina = AwaitClientChangeCipherSpec (server_ctx, client_ctx, master_secret, log @ [raw])
  in
  Tracing.cs ~tag:"master-secret" master_secret ;
  ({ state with machina = Server machina }, [])

let private_key config =
  match config.own_certificate with
    | Some (_, priv) -> return priv
    | None           -> fail_handshake

let answer_client_key_exchange_RSA state params kex raw log =
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
    (* we do not provide an option to disable the version checking (yet!) *)
    match Cstruct.len k == 48, Reader.parse_version k with
    | true, Reader.Or_error.Ok c_ver when c_ver = params.client_version -> k
    | _                                                                 -> other
  in

  private_key state.config >|= fun priv ->

  let pms = match RSA.PKCS1.decrypt priv kex with
    | None   -> validate_premastersecret other
    | Some k -> validate_premastersecret k
  in
  establish_master_secret state params pms raw log

let answer_client_key_exchange_DHE_RSA state params (group, secret) kex raw log =
  match Crypto.dh_shared group secret kex with
  | None     -> fail Packet.INSUFFICIENT_SECURITY
  | Some pms -> return (establish_master_secret state params pms raw log)

let versions = [ TLS_1_0 ; TLS_1_1 ; TLS_1_2 ]

let answer_client_hello state (ch : client_hello) raw =
  let find_version supported requested =
    let r =
      let c = Rng.generate 1 in
      Cstruct.get_uint8 c 0
    in
    match requested with
    | SSL_3   -> fail Packet.PROTOCOL_VERSION
    | TLS_1_0 -> return TLS_1_0
    | TLS_1_1 -> return (List.nth versions (r mod 2))
    | _       -> return (List.nth versions (r mod 3))

  and find_ciphersuite server_supported requested =
    let r =
      let c = Rng.generate 1 in
      Cstruct.get_uint8 c 0
    in
    match List_set.inter requested server_supported with
    | []   -> fail_handshake
    | xs   -> return (List.nth xs (r mod (List.length xs)))

  and ensure_reneg require our_data ciphers their_data  =
    let reneg_cs = List.mem Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV ciphers in
    match require, reneg_cs, our_data, their_data with
    | _    , _    , None         , Some x -> assure (Cs.null x)
    | _    , _    , Some (cvd, _), Some x -> assure (Cs.equal cvd x)
    | _    , true , None         , _      -> return ()
    | false, _    , _            , _      -> return ()
    | true , _    , _            , _      -> fail_handshake

  (* only renegotiate if the config allows us to *)
  and renegotiate use_reneg reneg =
    match use_reneg, reneg with
    | false, Some _ -> fail_handshake
    | _    , _      -> return ()
  in

  let process_client_hello config ch =
    let cciphers = ch.ciphersuites in
    let theirs = get_secure_renegotiation ch.extensions in
    assure (client_hello_valid ch) >>= fun () ->
    find_version config.protocol_versions ch.version >>= fun version ->
    find_ciphersuite config.ciphers cciphers >>= fun cipher ->
    renegotiate config.use_reneg state.reneg >>= fun () ->
    ensure_reneg config.secure_reneg state.reneg cciphers theirs >|= fun () ->

    Tracing.sexpf ~tag:"version" ~f:sexp_of_tls_version version ;
    Tracing.sexpf ~tag:"cipher" ~f:Ciphersuite.sexp_of_ciphersuite cipher ;

    ({ server_random = Rng.generate 32 ;
       client_random = ch.random ;
       client_version = ch.version ;
       cipher = cipher },
     version)

  and server_hello client_hello cipher reneg version random =
    (* we could provide a certificate with any of the given hostnames *)
    (* TODO: preserve this hostname somewhere maybe? *)
    let server_name = hostname client_hello in

    let server_hello =
      (* RFC 4366: server shall reply with an empty hostname extension *)
      let host = option [] (fun _ -> [Hostname None]) server_name
      and secren =
        match reneg with
        | None            -> SecureRenegotiation (Cstruct.create 0)
        | Some (cvd, svd) -> SecureRenegotiation (cvd <+> svd)
      in
      { version      = version ;
        random       = random ;
        sessionid    = None ;
        ciphersuites = cipher ;
        extensions   = secren :: host }
    in
    let sh = ServerHello server_hello in
    Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake sh ;
    Writer.assemble_handshake sh

  and server_cert config cipher params =
    let cert_needed =
      Ciphersuite.(needs_certificate @@ ciphersuite_kex cipher) in
    match config.own_certificate, cert_needed with
    | Some (certs, _), true ->
       let cert = Certificate (List.map Certificate.cs_of_cert certs) in
       Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake cert ;
       return [ Writer.assemble_handshake cert ]
    | _, false -> return []
    | _        -> fail_handshake
    (* ^^^ Rig ciphersuite selection never to end up with one than needs a cert
     * if we haven't got one. *)

  and kex_dhe_rsa config params version client_hello =
    let group         = DH.Group.oakley_2 in (* rfc2409 1024-bit group *)
    let (secret, msg) = DH.gen_secret group in
    let dh_state      = group, secret in
    let written =
      let dh_param = Crypto.dh_params_pack group msg in
      Writer.assemble_dh_parameters dh_param in

    let data = params.client_random <+> params.server_random <+> written in

    let signature pk =

      let sign x =
        match RSA.PKCS1.sign pk x with
        | None        -> fail_handshake
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
                List.(map fst @@ filter (fun (_, x) -> x = Packet.RSA) client_algos)
              in
              match first_match client_hashes supported_hashes with
              | None      -> fail_handshake
              | Some hash -> return hash )
          >>= fun hash ->
            match Crypto.pkcs1_digest_info_to_cstruct hash data with
            | None         -> fail_handshake
            | Some to_sign ->
                sign to_sign >|= Writer.assemble_digitally_signed_1_2 hash Packet.RSA
    in

    private_key state.config >>= signature >|= fun sgn ->
      let kex = ServerKeyExchange (written <+> sgn) in
      let hs = Writer.assemble_handshake kex in
      Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake kex ;
      (hs, dh_state) in

  process_client_hello state.config ch >>= fun (params, version) ->
  let cipher = params.cipher in
  let sh = server_hello ch cipher state.reneg version params.server_random in
  server_cert state.config cipher params >>= fun certificates ->

  let hello_done = Writer.assemble_handshake ServerHelloDone in

  ( match Ciphersuite.ciphersuite_kex cipher with
    | Ciphersuite.DHE_RSA ->
        kex_dhe_rsa state.config params version ch >>= fun (kex, dh) ->
        let outs = sh :: certificates @ [ kex ; hello_done] in
        let machina = AwaitClientKeyExchange_DHE_RSA (params, dh, raw :: outs) in
        Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake ServerHelloDone ;
        return (outs, machina)
    | Ciphersuite.RSA ->
        let outs = sh :: certificates @ [ hello_done] in
        let machina = AwaitClientKeyExchange_RSA (params, raw :: outs) in
        Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake ServerHelloDone ;
        return (outs, machina)
    ) >|= fun (out_recs, machina) ->

  ({ state with machina = Server machina ; version },
   [`Record (Packet.HANDSHAKE, Cs.appends out_recs)])

let handle_change_cipher_spec ss state packet =
  let open Reader in
  match parse_change_cipher_spec packet, ss with
  | Or_error.Ok (), AwaitClientChangeCipherSpec (server_ctx, client_ctx, master_secret, log) ->
     assure (Cs.null state.hs_fragment)
     >>= fun () ->
     let ccs = change_cipher_spec in
     let machina = AwaitClientFinished (master_secret, log)
     in
     Tracing.cs ~tag:"change-cipher-spec-in" packet ;
     Tracing.cs ~tag:"change-cipher-spec-out" packet ;

     return ({ state with machina = Server machina },
             [`Record ccs; `Change_enc (Some server_ctx)],
             `Change_dec (Some client_ctx))
  | _ ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_handshake ss hs buf =
  let open Reader in
  match parse_handshake buf with
  | Or_error.Ok handshake ->
     Tracing.sexpf ~tag:"handshake-in" ~f:sexp_of_tls_handshake handshake;
     ( match ss, handshake with
       | AwaitClientHello, ClientHello ch ->
          answer_client_hello hs ch buf
       | AwaitClientKeyExchange_RSA (params, log), ClientKeyExchange kex ->
          answer_client_key_exchange_RSA hs params kex buf log
       | AwaitClientKeyExchange_DHE_RSA (params, dh_sent, log), ClientKeyExchange kex ->
          answer_client_key_exchange_DHE_RSA hs params dh_sent kex buf log
       | AwaitClientFinished (master_secret, log), Finished fin ->
          answer_client_finished hs master_secret fin buf log
       | Established, ClientHello ch -> (* renegotiation *)
          answer_client_hello hs ch buf
       | _, _-> fail_handshake )
  | Or_error.Error _ -> fail Packet.UNEXPECTED_MESSAGE

let hello_request hs =
  if Config.(hs.config.use_rekeying) then
    let hr = Writer.assemble_handshake HelloRequest in
    return ({ hs with machina = Server AwaitClientHello }, [`Record (Packet.HANDSHAKE, hr)])
  else
    fail_handshake
