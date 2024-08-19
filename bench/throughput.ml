let now = Ptime_clock.now

let cert ~digest ~key =
  let subject =
    let open X509.Distinguished_name in
    [ Relative_distinguished_name.singleton (CN "ocaml-tls") ]
  in
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
         (true,
          [ `Key_cert_sign
          ; `CRL_sign
          ; `Digital_signature
          ; `Content_commitment
          ; `Key_encipherment ])
    |> add Ext_key_usage (true, [ `Server_auth ])
  in
  let valid_from = now () in
  let valid_until = Ptime.add_span valid_from (Ptime.Span.of_int_s 60) in
  let valid_until = Option.get valid_until in
  let cert = X509.Signing_request.sign csr ~valid_from ~valid_until ~digest
    ~extensions key subject in
  match cert with
  | Ok cert -> cert
  | Error e -> Fmt.failwith "cert error %a" X509.Validation.pp_signature_error e

let authenticator ?ip:_ ~host:_ _certs = Ok None

let consume state input =
  match Tls.Engine.handle_tls state input with
  | Ok (state, Some `Eof, `Response out, `Data v) ->
      let data = Option.fold ~none:0 ~some:Cstruct.length v in
      `Eof state, out, data
  | Ok (state, None, `Response out, `Data v) ->
      let data = Option.fold ~none:0 ~some:Cstruct.length v in
      `Continue state, out, data
  | Error (err, `Response out) ->
      `Error err, Some out, 0

let to_state state input =
  match consume state input with
  | `Eof _, _, _ -> Fmt.failwith "Unexpected eof"
  | `Error err, _, _ -> Fmt.failwith "Unexpected error: %a" Tls.Engine.pp_failure err
  | `Continue state, out, data -> state, out, data

type flow =
  | To_client of Tls.Engine.state * Tls.Engine.state * Cstruct.t option
  | To_server of Tls.Engine.state * Tls.Engine.state * Cstruct.t option

type state =
  { flow : flow
  ; server_out : int
  ; client_out : int
  ; direction : [ `To_server | `To_client ] }

let make ?groups ~cipher ~digest ~key version direction =
  let cert = cert ~digest ~key in
  let client_cfg = Tls.Config.client ?groups ~version:(version, version)
    ~ciphers:[ cipher ] ~authenticator ()
  and server_cfg = Tls.Config.server ~certificates:(`Single ([ cert ], key)) () in
  let client_state, client_out = Tls.Engine.client client_cfg
  and server_state = Tls.Engine.server server_cfg in
  { flow= To_server (client_state, server_state, Some client_out)
  ; server_out= 0
  ; client_out= 0
  ; direction }

let actually_send_application_data client_state server_state direction buf =
  match direction with
  | `To_server ->
      let[@warning "-8"] Some (client_state, to_server) =
        Tls.Engine.send_application_data client_state [ buf ] in
      To_server (client_state, server_state, Some to_server)
  | `To_client ->
      let[@warning "-8"] Some (server_state, to_client) =
        Tls.Engine.send_application_data server_state [ buf ] in
      To_client (client_state, server_state, Some to_client)

let rec once state buf = match state.flow, buf with
  | To_server (client_state, server_state, None), Some buf
  | To_client (client_state, server_state, None), Some buf ->
      let flow = actually_send_application_data
        client_state server_state state.direction buf in
      once { state with flow } None
  | To_server (_, _, None), None
  | To_client (_, _, None), None -> state
  | To_server (client_state, server_state, Some to_server), buf ->
      let server_state, to_client, n = to_state server_state to_server in
      let flow = To_client (client_state, server_state, to_client) in
      once { state with flow; server_out= state.server_out + n } buf
  | To_client (client_state, server_state, Some to_client), _ ->
      let client_state, to_server, n = to_state client_state to_client in
      let flow = To_server (client_state, server_state, to_server) in
      once { state with flow; client_out= state.client_out + n } buf

let to_consumer state =
  let state = ref state in
  fun buf -> state := once !state (Some buf)

module Time = struct
  let time ~n fn size =
    let bufs = Array.init n begin fun _ ->
      Mirage_crypto_rng.generate size
    end in
    let t1 = Sys.time () in
    for i = 0 to n - 1 do ignore (fn bufs.(i)) done;
    let t2 = Sys.time () in
    (t2 -. t1)
end

let burn_period = 2.0
let sizes = [ 16; 64; 256; 1024; 4096; 8192 ]

let burn fn size =
  let (t1, i1) =
    let rec go it =
      let t = Time.time ~n:it fn size in
      if t > 0.2 then (t, it) else go (it * 10) in
    go 10 in
  let iters = int_of_float (float i1 *. burn_period /. t1) in
  let time = Time.time ~n:iters fn size in
  (iters, time, float (size * iters) /. time)

let mb = 1024. *. 1024.

let throughput title fn =
  Fmt.pr "\n* [%s]\n%!" title ;
  List.iter begin fun size ->
    Gc.full_major ();
    let (iters, time, bw) = burn fn size in
    Fmt.pr "   % 5d:  %04.04f MB/s (%d iters in %.03fs)\n%!"
      size (bw /. mb) iters time
  end sizes

let bm name fn = (name, fun () -> fn name)

let benchmarks =
  [ bm "tls-1.3, rsa/2048, x25519, aes-128-gcm-sha256" begin fun name ->
      let key = X509.Private_key.generate ~bits:2048 `RSA in
      let state = make ~groups:[ `X25519 ] ~cipher:`AES_128_GCM_SHA256 ~digest:`SHA256 ~key `TLS_1_3 `To_server in
      throughput name (to_consumer state)
    end
  ; bm "tls-1.3, rsa/2048, p256, aes-128-gcm-sha256" begin fun name ->
      let key = X509.Private_key.generate ~bits:2048 `RSA in
      let state = make ~groups:[ `P256 ] ~cipher:`AES_128_GCM_SHA256 ~digest:`SHA256 ~key `TLS_1_3 `To_server in
      throughput name (to_consumer state)
    end
  ; bm "tls-1.3, rsa/2048, x25519, chacha20-poly1305-sha256" begin fun name ->
      let key = X509.Private_key.generate ~bits:2048 `RSA in
      let state = make ~groups:[ `X25519 ] ~cipher:`CHACHA20_POLY1305_SHA256 ~digest:`SHA256 ~key `TLS_1_3 `To_server in
      throughput name (to_consumer state)
    end

  ]

let run fns =
  List.iter (fun (_, fn) -> fn ()) fns

let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)

let () =
  let seed = Cstruct.of_string "0xdeadbeef" in
  let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
  Mirage_crypto_rng.set_default_generator g;
  run benchmarks

