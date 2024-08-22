let rec random_path ?(tries = 10) fmt =
  if tries <= 0 then failwith "Impossible to generate an available random path";
  let res = Bytes.create 6 in
  for i = 0 to Bytes.length res - 1 do
    let chr =
      match Random.int (10 + 26 + 26) with
      | n when n < 10 -> Char.chr (Char.code '0' + n)
      | n when n < 10 + 26 -> Char.chr (Char.code 'a' + n - 10)
      | n -> Char.chr (Char.code 'A' + n - 10 - 26)
    in
    Bytes.set res i chr
  done;
  let path = Fmt.str fmt (Bytes.unsafe_to_string res) in
  if Sys.file_exists path then random_path ~tries:(pred tries) fmt else path

let unlink_if_exists path =
  try Unix.unlink path with Unix.Unix_error (Unix.ENOENT, _, _) -> ()

let bind_and_listen ?(backlog = 16) () =
  let tmp = random_path "socket-%s.socket" in
  unlink_if_exists tmp;
  let socket = Unix.socket ~cloexec:true Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let addr = Unix.ADDR_UNIX tmp in
  Unix.bind socket addr;
  Unix.listen socket backlog;
  (Miou_unix.of_file_descr ~non_blocking:true socket, addr, tmp)

module Ca = struct
  open Rresult

  let prefix =
    X509.Distinguished_name.
      [ Relative_distinguished_name.singleton (CN "Fuzzer") ]

  let cacert_dn =
    X509.Distinguished_name.(
      prefix
      @ [ Relative_distinguished_name.singleton (CN "Ephemeral CA for fuzzer") ])

  let cacert_lifetime = Ptime.Span.v (365, 0L)
  let _10s = Ptime.Span.of_int_s 10

  let make domain_name seed =
    let valid_from = Option.get Ptime.(sub_span (v (Ptime_clock.now_d_ps ())) _10s) in
    Domain_name.of_string domain_name >>= Domain_name.host
    >>= fun domain_name ->
    let private_key =
      let seed = Base64.decode_exn ~pad:false seed in
      let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
      Mirage_crypto_pk.Rsa.generate ~g ~bits:2048 ()
    in
    Ptime.add_span valid_from cacert_lifetime
    |> Option.to_result ~none:(R.msgf "End time out of range")
    >>= fun valid_until ->
    X509.Signing_request.create cacert_dn (`RSA private_key) >>= fun ca_csr ->
    let extensions =
      let open X509.Extension in
      let key_id =
        X509.Public_key.id X509.Signing_request.((info ca_csr).public_key)
      in
      empty
      |> add Subject_alt_name
           ( true,
             X509.General_name.(
               singleton DNS [ Domain_name.to_string domain_name ]) )
      |> add Basic_constraints (true, (false, None))
      |> add Key_usage
           (true, [ `Digital_signature; `Content_commitment; `Key_encipherment ])
      |> add Subject_key_id (false, key_id)
    in
    X509.Signing_request.sign ~valid_from ~valid_until ~extensions
      ca_csr (`RSA private_key) cacert_dn
    |> R.reword_error (R.msgf "%a" X509.Validation.pp_signature_error)
    >>= fun certificate ->
    let fingerprint = X509.Certificate.fingerprint `SHA256 certificate in
    let time () = Some (Ptime_clock.now ()) in
    let authenticator =
      X509.Authenticator.cert_fingerprint ~time ~hash:`SHA256
        ~fingerprint
    in
    Ok (certificate, `RSA private_key, authenticator)
end

let fuzz_coop = "fuzz.coop"
let mutex = Miou.Mutex.create ()
let epr fmt = Miou.Mutex.protect mutex @@ fun () -> Fmt.epr fmt

type operation =
  | Send of string
  | Recv of int
  | Shutdown of [ `read | `write ]
  | Close
  | Noop

module Stop = struct
  type t = {
    mutex : Miou.Mutex.t;
    condition : Miou.Condition.t;
    mutable stop : bool;
  }

  let create () =
    let mutex = Miou.Mutex.create () in
    let condition = Miou.Condition.create () in
    { mutex; condition; stop = false }

  let stop t =
    Miou.Mutex.protect t.mutex @@ fun () ->
    t.stop <- true;
    Miou.Condition.broadcast t.condition

  let wait t =
    Miou.Mutex.protect t.mutex @@ fun () ->
    while t.stop = false do
      Miou.Condition.wait t.condition t.mutex
    done
end

let inhibit fn = try fn () with _exn -> ()

let run ~role:_ actions tls =
  let rec go buf tls = function
    | [] -> Buffer.contents buf
    | Noop :: actions ->
        Miou.yield ();
        go buf tls actions
    | Send str :: actions ->
        Tls_miou_unix.write tls str;
        go buf tls actions
    | Close :: actions ->
        Tls_miou_unix.close tls;
        go buf tls actions
    | Shutdown cmd :: actions ->
        Tls_miou_unix.shutdown tls (cmd :> [ `read | `write | `read_write ]);
        go buf tls actions
    | Recv len :: actions ->
        let tmp = Bytes.make len '\000' in
        Tls_miou_unix.really_read tls tmp;
        Buffer.add_subbytes buf tmp 0 len;
        go buf tls actions
  in
  let buf = Buffer.create 0x100 in
  try go buf tls actions with
  | End_of_file | Tls_miou_unix.Closed_by_peer | Tls_miou_unix.Tls_alert _
  | Tls_miou_unix.Tls_failure _ ->
      inhibit (fun () -> Miou_unix.close (Tls_miou_unix.file_descr tls));
      Buffer.contents buf
  | exn ->
      inhibit (fun () -> Miou_unix.close (Tls_miou_unix.file_descr tls));
      raise exn

let run_client ~to_client:actions cfg addr =
  let domain = Unix.domain_of_sockaddr addr in
  let socket = Unix.socket ~cloexec:true domain Unix.SOCK_STREAM 0 in
  Unix.connect socket addr;
  let fd = Miou_unix.of_file_descr ~non_blocking:true socket in
  let tls = Tls_miou_unix.client_of_fd cfg fd in
  let finally () =
    inhibit (fun () -> Unix.close socket)
  in
  Fun.protect ~finally @@ fun () -> run ~role:"client" actions tls

let rec cleanup orphans clients =
  match Miou.care orphans with
  | None | Some None -> clients
  | Some (Some prm) ->
      let clients = Miou.await prm :: clients in
      cleanup orphans clients

let rec terminate orphans clients =
  match Miou.care orphans with
  | None -> List.rev clients
  | Some None ->
      Miou.yield ();
      terminate orphans clients
  | Some (Some prm) ->
      let clients = Miou.await prm :: clients in
      terminate orphans clients

exception Stop

let run_server ~to_server:actions ~stop fd cfg =
  let rec go orphans clients =
    let clients = cleanup orphans clients in
    let accept = Miou.async @@ fun () -> Miou_unix.accept ~cloexec:true fd in
    let stop =
      Miou.async @@ fun () ->
      Stop.wait stop;
      raise Stop
    in
    match Miou.await_first [ accept; stop ] with
    | Error _ ->
        inhibit (fun () -> Miou_unix.close fd);
        terminate orphans clients
    | Ok (fd, _) ->
        ignore
          ( Miou.async ~orphans @@ fun () ->
            match Tls_miou_unix.server_of_fd cfg fd with
            | tls ->
                let str = run ~role:"server" actions tls in
                inhibit (fun () -> Miou_unix.close fd); str
            | exception _ ->
                Miou_unix.close fd;
                String.empty );
        go orphans clients
  in
  go (Miou.orphans ()) []

let compile to_client to_server =
  let close_client close = function
    | Close -> close lor 0b1100
    | Shutdown `read -> close lor 0b1000
    | Shutdown `write -> close lor 0b0100
    | _ -> close
  in
  let close_server close = function
    | Close -> close lor 0b0011
    | Shutdown `read -> close lor 0b0010
    | Shutdown `write -> close lor 0b0001
    | _ -> close
  in
  let client = Buffer.create 0x100 in
  let server = Buffer.create 0x100 in
  let rec go close to_client to_server =
    match (close, to_client, to_server) with
    | _, [], _ | _, _, [] -> ()
    | close, ((Shutdown _ | Close) as operation) :: to_client, _ ->
        go (close_client close operation) to_client to_server
    | close, _, ((Shutdown _ | Close) as operation) :: to_server ->
        go (close_server close operation) to_client to_server
    | close, Noop :: to_client, to_server | close, to_client, Noop :: to_server
      ->
        go close to_client to_server
    | close, Send str :: to_client, Recv n :: to_server ->
        assert (String.length str = n);
        if close land 0b0100 = 0 && close land 0b0010 = 0 then
          Buffer.add_string server str;
        if close land 0b0100 = 0 && close land 0b0010 = 0 then
          go close to_client to_server
    | close, Recv n :: to_client, Send str :: to_server ->
        assert (String.length str = n);
        if close land 0b1000 = 0 && close land 0b0001 = 0 then
          Buffer.add_string client str;
        if close land 0b1000 = 0 && close land 0b0001 = 0 then
          go close to_client to_server
    | _, Send _ :: _, Send _ :: _ | _, Recv _ :: _, Recv _ :: _ ->
        assert false (* GADT? *)
  in
  go 0x0 to_client to_server;
  (Buffer.contents client, Buffer.contents server)

let pp_exn ppf exn = Fmt.string ppf (Printexc.to_string exn)
let pp_str ppf str = Hxd_string.pp Hxd.default ppf str

let run seed operations =
  Miou_unix.run ~domains:1 @@ fun () ->
  let rng = Mirage_crypto_rng_miou_unix.(initialize (module Pfortuna)) in
  let fd, addr, path = bind_and_listen () in
  let finally () = Unix.unlink path in
  Fun.protect ~finally @@ fun () ->
  let cert, pk, authenticator =
    Rresult.R.failwith_error_msg (Ca.make fuzz_coop seed)
  in
  let cfg_server =
    Result.get_ok (Tls.Config.server ~certificates:(`Single ([ cert ], pk)) ())
  in
  let cfg_client = Result.get_ok (Tls.Config.client ~authenticator ()) in
  let to_client, to_server = List.split operations in
  let stop = Stop.create () in
  let prm0 = Miou.async @@ fun () -> run_server ~to_server ~stop fd cfg_server in
  let prm1 =
    Miou.async @@ fun () ->
    let finally () = Stop.stop stop in
    Fun.protect ~finally @@ fun () -> run_client ~to_client cfg_client addr
  in
  let send_to_client, send_to_server = compile to_client to_server in
  match (Miou.await prm0, Miou.await prm1) with
  | Ok [ Ok send_to_server' ], Ok send_to_client' ->
      Crowbar.check (String.equal send_to_client send_to_client');
      Crowbar.check (String.equal send_to_server send_to_server');
      let n = String.length send_to_client in
      let m = String.length send_to_server in
      Mirage_crypto_rng_miou_unix.kill rng;
      epr "[%a] %db %db transmitted\n%!" Fmt.(styled `Green string) "OK" n m
  | a, b ->
      Mirage_crypto_rng_miou_unix.kill rng;
      Crowbar.failf "[%a] Unexpected result: %a & %a\n%!"
        Fmt.(styled `Red string) "ERROR"
        Fmt.(Dump.result ~error:pp_exn ~ok:Fmt.(Dump.list (Dump.result ~error:pp_exn ~ok:pp_str))) a
        Fmt.(Dump.result ~error:pp_exn ~ok:pp_str) b

let label name gen = Crowbar.with_printer Fmt.(const string name) gen

let direction =
  let open Crowbar in
  choose
    [
      label "server-to-client" (const `To_client);
      label "client-to-server" (const `To_server);
    ]

let shutdown =
  let open Crowbar in
  choose
    [
      label "close" (const Close);
      label "shutdown-recv" (const (Shutdown `read));
      label "shutdown-send" (const (Shutdown `write));
      label "noop" (const Noop);
    ]

let operation =
  let open Crowbar in
  map [ direction; bytes ] @@ fun direction str ->
  match (direction, str) with
  | _, "" -> (Noop, Noop)
  | `To_server, str -> (Send str, Recv (String.length str))
  | `To_client, str -> (Recv (String.length str), Send str)

let counter = Atomic.make 0

let operations =
  let open Crowbar in
  fix @@ fun m ->
  let continue (to_client, to_server) =
    if Atomic.fetch_and_add counter 1 >= 4 then const [ (Close, Close) ]
    else map [ m ] @@ fun ops -> (to_client, to_server) :: ops
  in
  map
    [ list1 operation; dynamic_bind (pair shutdown shutdown) continue ]
    List.rev_append

let seed = Crowbar.(map [ bytes ] Base64.encode_exn)

let () =
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  Crowbar.add_test ~name:"run" Crowbar.[ seed; operations ] @@ fun seed operations ->
  run seed operations;
  Atomic.set counter 0
