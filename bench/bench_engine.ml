open Tls

let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)
let now = Ptime_clock.now

let key = X509.Private_key.generate ~bits:2048 `RSA

let _ca, cert =
  let subject =
    [
      X509.Distinguished_name.(
        Relative_distinguished_name.singleton (CN "Miragevpn snakeoil"));
    ]
  in
  let digest = `SHA256 in
  let csr = X509.Signing_request.create ~digest subject key |> Result.get_ok in
  let pubkey = (X509.Signing_request.info csr).public_key in
  let extensions =
    let open X509.Extension in
    let auth =
      (Some (X509.Public_key.id pubkey), X509.General_name.empty, None)
    in
    singleton Authority_key_id (false, auth)
    |> add Subject_key_id (false, X509.Public_key.id pubkey)
    |> add Basic_constraints (true, (true, None))
    |> add Key_usage
         ( true,
           [
             `Key_cert_sign;
             `CRL_sign;
             `Digital_signature;
             `Content_commitment;
             `Key_encipherment;
           ] )
    |> add Ext_key_usage (true, [ `Server_auth ])
  in
  let valid_from = now () in
  let valid_until =
    Ptime.add_span valid_from (Ptime.Span.of_int_s 60) |> Option.get
  in
  let cert =
    match
      X509.Signing_request.sign csr ~valid_from ~valid_until ~digest ~extensions
        key subject
    with
    | Ok cert -> cert
    | Error e ->
        Format.kasprintf failwith "cert error %a"
          X509.Validation.pp_signature_error e
  in
  (cert, cert)

let established version cipher =
  let client_config =
    let authenticator ?ip:_ ~host:_ _certs = Ok None in
    Config.client ~version:(version, version) ~ciphers:[cipher] ~authenticator ()
  and server_config =
    let certificates = `Single ([ cert ], key) in
    Config.server ~certificates ()
  in

  let ( initial_client, initial_client_out ) = Engine.client client_config in

  let initial_server = Engine.server server_config in

  let drain role state input =
    match Engine.handle_tls state input with
    | Ok (_state, Some `Eof, _, _) ->
      invalid_arg (role ^ " ran into eof")
    | Ok (_state, None, _, `Data (Some _)) ->
      invalid_arg (role ^ " ran into data")
    | Ok (state, None, `Response resp, `Data None) ->
      state, resp
    | Error (e, _response) ->
      Format.kasprintf failwith "%s error: %a" role Engine.pp_failure e
  in
  let rec go client server client_out = match client_out with
    | None -> client, server
    | Some out ->
      let server, server_out = drain "Server" server out in
      match server_out with
      | None -> client, server
      | Some out ->
        let client, client_out = drain "Client" client out in
        go client server client_out
  in
  let client, server = go initial_client initial_server (Some initial_client_out) in
  assert (Engine.handshake_in_progress client = false);
  assert (Engine.handshake_in_progress server = false);
  client, server

open Bechamel

let test_send_data version cipher =
  let staged =
    let established_client, _ = established version cipher in
    let data = Cstruct.create 1024 in
    Staged.stage @@ fun () ->
    match Engine.send_application_data established_client [ data ] with
    | Some _ -> ()
    | None -> assert false
  in
  Test.make ~name:"send" staged

let test_receive_data version cipher =
  let staged =
    let established_client, established_server = established version cipher in
    let data = Cstruct.create 1024 in
    let pkt =
      match Engine.send_application_data established_server [ data ] with
      | Some (_state, pkt) -> pkt
      | None -> assert false
    in
    Staged.stage @@ fun () ->
    match Engine.handle_tls established_client pkt with
    | Ok _ -> ()
    | Error _ -> assert false
  in
  Test.make ~name:"receive" staged

let version_ciphers =
  List.map (fun cipher -> `TLS_1_2, cipher) [
    `DHE_RSA_WITH_AES_128_GCM_SHA256 ;
    `DHE_RSA_WITH_AES_128_CCM ;
    `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ;
  ] @
  List.map (fun cipher -> `TLS_1_3, cipher)
    [ `AES_128_GCM_SHA256 ; `CHACHA20_POLY1305_SHA256 ; `AES_128_CCM_SHA256 ]

let test_client =
  Test.make_grouped ~name:""
    (List.map
       (fun (version, cipher) ->
          Test.make_grouped
            ~name:(Fmt.str "%a %a" Core.pp_tls_version version Ciphersuite.pp_ciphersuite cipher)
            [ test_send_data version cipher; test_receive_data version cipher ])
       version_ciphers)

let benchmark () =
  let ols =
    Analyze.ols ~bootstrap:0 ~r_square:true ~predictors:Measure.[| run |]
  in
  let instances =
    Toolkit.Instance.[ minor_allocated; major_allocated; monotonic_clock ]
  in
  let cfg =
    Benchmark.cfg ~limit:2000 ~quota:(Time.second 0.5) ~kde:(Some 1000) ()
  in
  let raw_results = Benchmark.all cfg instances test_client in
  let results =
    List.map (fun instance -> Analyze.all ols instance raw_results) instances
  in
  let results = Analyze.merge ols instances results in
  (results, raw_results)

let () =
  List.iter
    (fun v -> Bechamel_notty.Unit.add v (Measure.unit v))
    Toolkit.Instance.[ minor_allocated; major_allocated; monotonic_clock ]

let img (window, results) =
  Bechamel_notty.Multiple.image_of_ols_results ~rect:window
    ~predictor:Measure.run results

open Notty_unix

let () =
  let window =
    match winsize Unix.stdout with
    | Some (w, h) -> { Bechamel_notty.w; h }
    | None -> { Bechamel_notty.w = 80; h = 1 }
  in
  let results, _ = benchmark () in
  img (window, results) |> eol |> output_image
