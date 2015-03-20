open Tracer_common

open Tls

module Reader = struct
  open Sexplib
  open Sexplib.Sexp
  open Sexplib.Conv

  open Tls
  open Core
  open Packet
  open State

  let client_ctx = ref None
  let server_ctx = ref None

  let buf_in_table = Hashtbl.create 7

  let parse_ch = Core.client_hello_of_sexp
  let parse_sh = Core.server_hello_of_sexp
  let parse_log = State.hs_log_of_sexp
  let parse_session_data = State.session_data_of_sexp
  let parse_cstruct = Cstruct.t_of_sexp

  let conv_hs_client ver = function
    | List [ Atom "AwaitServerChangeCipherSpec" ; session_data ; _ ; chk ; hs_log ] ->
      let s = parse_session_data session_data in
      let c_ctx, s_ctx = Handshake_crypto.make_context s.ciphersuite ver s.master_secret s.server_random s.client_random in
      client_ctx := Some c_ctx ;
      server_ctx := Some s_ctx ;
      AwaitServerChangeCipherSpec (s, s_ctx, parse_cstruct chk, parse_log hs_log)
    | x -> State.client_handshake_state_of_sexp x

  let conv_hs_server ver = function
    | List [ Atom "AwaitClientCertificateVerify" ; session_data ; _ ; _ ; hs_log ] ->
      let s = parse_session_data session_data in
      let c_ctx, s_ctx = Handshake_crypto.make_context s.ciphersuite ver s.master_secret s.server_random s.client_random in
      client_ctx := Some c_ctx ;
      server_ctx := Some s_ctx ;
      AwaitClientCertificateVerify (s, s_ctx, c_ctx, parse_log hs_log)
    | List [ Atom "AwaitClientChangeCipherSpec" ; session_data ; _ ; _ ; hs_log ] ->
      let s = parse_session_data session_data in
      let c_ctx, s_ctx = Handshake_crypto.make_context s.ciphersuite ver s.master_secret s.server_random s.client_random in
      client_ctx := Some c_ctx ;
      server_ctx := Some s_ctx ;
      AwaitClientChangeCipherSpec (s, s_ctx, c_ctx, parse_log hs_log)
    | x -> State.server_handshake_state_of_sexp x

  let conv_hs_machina ver xs =
    match ver, xs with
    | Some v, List [ Atom "Server" ; xs ] -> Server (conv_hs_server v xs)
    | Some v, List [ Atom "Client" ; xs ] -> Client (conv_hs_client v xs)
    | _ -> assert false

  let conv_hs config = function
    | List xs ->
      begin
        match
          List.fold_left (fun (sess, ver, mac, frag) x -> match x with
              | List [ Atom "session" ; xs ] ->
                (Some (list_of_sexp parse_session_data xs), ver, mac, frag)
              | List [ Atom "protocol_version" ; ver ] ->
                (sess, Some (tls_version_of_sexp ver), mac, frag)
              | List [ Atom "machina" ; m ] ->
                (sess, ver, Some (conv_hs_machina ver m), frag)
              | List [ Atom "config" ; _ ] ->
                (sess, ver, mac, frag)
              | List [ Atom "hs_fragment" ; xs ] ->
                (sess, ver, mac, Some (parse_cstruct xs))
              | _ -> assert false)
            (None, None, None, None) xs
        with
        | Some session, Some protocol_version, Some machina, Some hs_fragment ->
          ({ session ; protocol_version ; machina ; config ; hs_fragment })
        | _ -> assert false
      end
    | _ -> assert false

  let find_dec_enc proj = function
    | Some l -> proj l
    | _ -> assert false

  let update x = function
    | List [ List [ List [ Atom "sequence" ; seq ] ; List [ Atom "cipher_st" ; _ ] ] ] ->
      let sequence = int64_of_sexp seq in
      { x with sequence }
    | _ -> assert false

  let conv_state last config = function
    | List xs ->
      begin
        match
          List.fold_left (fun (hs, dec, enc, frag) x -> match x with
              | List [ Atom "handshake" ; xs ] ->
                (Some (conv_hs config xs), dec, enc, frag)
              | List [ Atom "decryptor" ; List [] ] ->
                (* Printf.printf "decryptor None\n"; *)
                (hs, Some None, enc, frag)
              | List [ Atom "encryptor" ; List [] ] ->
                (* Printf.printf "encryptor None\n"; *)
                (hs, dec, Some None, frag)
              | List [ Atom "decryptor" ; dec ] ->
                (* Printf.printf "s_ctx %s\n decryptor %s\n"
                  (to_string_hum (sexp_of_option sexp_of_crypto_context !server_ctx))
                   (to_string_hum dec); *)
                let ctx = match !server_ctx, last with
                  | Some x, _ -> server_ctx := None ; x
                  | None, Some x -> (match find_dec_enc (fun x -> x.decryptor) last with
                      | Some x -> x
                      | None ->
                        (* we're in deep shit, let's compute! *)
                        let s, v = match hs with Some hs -> (List.hd (hs.session), hs.protocol_version) | None -> assert false in
                        let c_ctx, s_ctx = Handshake_crypto.make_context
                            s.ciphersuite v s.master_secret s.server_random s.client_random in
                        client_ctx := Some c_ctx ;
                        s_ctx)
                  | _ -> assert false
                in
                let ctx = update ctx dec in
                (* Printf.printf " is %s\n" (to_string_hum (sexp_of_crypto_context ctx)); *)
                (hs, Some (Some ctx), enc, frag)
              | List [ Atom "encryptor" ; enc ] ->
                (* Printf.printf "c_ctx %s\n encryptor %s,"
                  (to_string_hum (sexp_of_option sexp_of_crypto_context !client_ctx))
                   (to_string_hum enc); *)
                let ctx = match !client_ctx, last with
                  | Some x, _ -> client_ctx := None ; x
                  | None, Some x -> (match find_dec_enc (fun x -> x.encryptor) last with
                      | Some x -> x
                      | None -> assert false)
                  | _ -> assert false
                in
                let ctx = update ctx enc in
                (* Printf.printf " is %s\n" (to_string_hum (sexp_of_crypto_context ctx)); *)
                (hs, dec, Some (Some ctx), frag)
              | List [ Atom "fragment" ; xs ] ->
                (hs, dec, enc, Some (parse_cstruct xs))
              | _ -> assert false)
            (None, None, None, None) xs
        with
        | Some handshake, Some decryptor, Some encryptor, Some fragment ->
          State.({ handshake ; decryptor ; encryptor ; fragment })
        | _ -> assert false
      end
    | _ -> assert false

  let process_sexp config acc ele =
    let top =
      match
        Utils.filter_map ~f:(function `StateOut x -> Some x | _ -> None) acc
      with
      | [] -> None
      | x::_ -> Some x
    in
    let cur =
      (* try *)
        match ele with
        | List [ Atom "record-in" ; List [ List [ List [ Atom "content_type" ; ct ] ; List [ Atom "version" ; ver ] ] ; data ] ] ->
          let version = tls_any_version_of_sexp ver
          and content_type = content_type_of_sexp ct
          and data = parse_cstruct data
          in
          Some (`RecordIn ({ content_type ; version }, data))
        | List [ Atom "record-out" ; List [ ct ; data ] ] ->
          let content_type = content_type_of_sexp ct
          and data = parse_cstruct data
          in
          Some (`RecordOut (content_type, data))
        | List [ Atom "change-cipher-spec-in" ; _ ] ->
          Some `ChangeCipherSpecIn
        | List [ Atom "change-cipher-spec-out" ; _ ] ->
          Some `ChangeCipherSpecOut
        | List [ Atom "application-data-in" ; data ] ->
          Some (`ApplicationDataIn (parse_cstruct data))
        | List [ Atom "application-data-out" ; data ] ->
          Some (`ApplicationDataOut (parse_cstruct data))
        | List [ Atom "fail-alert-out" ; alert ] ->
          Some (`AlertOut (tls_alert_of_sexp alert))
        | List [ Atom "state-out" ; state ] ->
          Some (`StateOut (conv_state top config state))
        | List [ Atom "alert-in" ; al ] ->
          Some (`AlertIn (tls_alert_of_sexp al))
        | List [ Atom "ok-alert-out" ; al ] ->
          Some (`AlertOut (tls_alert_of_sexp al))
        | List [ Atom "failure" ; List [ Atom "Fatal" ; List [ Atom "UnexpectedHandshake" ; List [ Atom "ClientHello" ; data ] ] ] ]
        | List [ Atom "failure" ; List [ Atom "Fatal" ; List [ Atom "UnexpectedHandshake" ; List [ List [ Atom "Client" ; _ ] ; List [ Atom "ClientHello" ; data ] ] ] ] ] ->
          Some (`Failure (`Fatal (`UnexpectedHandshake (ClientHello (parse_ch data)))))
        | List [ Atom "failure" ; List [ Atom "Fatal" ; List [ Atom "UnexpectedHandshake" ; List [ Atom "ServerHello" ; data ] ] ] ] ->
          Some (`Failure (`Fatal (`UnexpectedHandshake (ServerHello (parse_sh data)))))
        | List [ Atom "failure" ; List [ Atom "Fatal" ; List [ Atom "UnexpectedHandshake" ; List [ Atom "Certificate" ; data ] ] ] ] ->
          Some (`Failure (`Fatal (`UnexpectedHandshake (Certificate (list_of_sexp parse_cstruct data)))))
        | List [ Atom "failure" ; List [ Atom "Error" ; Atom "NoSecureRenegotiation" ] ] ->
          (* yeah, I renamed this at some point *)
          Some (`Failure (`Fatal `NoSecureRenegotiation))
        | List [ Atom "failure" ; List [ Atom "Error" ; List [ Atom "AuthenticationFailure" ; Atom "NoCertificate" ] ] ] ->
          (* yeah, I renamed this at some point *)
          Some (`Failure (`Error (`AuthenticationFailure `EmptyCertificateChain)))
        | List [ Atom "failure" ; List [ Atom "Error" ; List [ Atom "AuthenticationFailure" ; List [ Atom "InvalidSignature" ; a ; b ] ] ] ] ->
          (* yeah, I renamed this at some point *)
          let a = X509.t_of_sexp a
          and b = X509.t_of_sexp b
          in
          Some (`Failure (`Error (`AuthenticationFailure (`InvalidSignature (a, b)))))
        | List [ Atom "failure" ; error ] ->
          Some (`Failure (Engine.failure_of_sexp error))
        | List [ Atom "buf-in" ; buf ] ->
          let buf_in = parse_cstruct buf in
          let k = Cstruct.to_string buf_in in
          (if Hashtbl.mem buf_in_table k then
             Hashtbl.replace buf_in_table k (succ (Hashtbl.find buf_in_table k))
           else
             Hashtbl.add buf_in_table k 1) ;
          Some (`BufIn buf_in)
        | Atom "*TIMEOUT*" ->
          Some `TimeOut
        | List [ Atom "eof-out" ; _ ] ->
          Some `Eof
        | x -> Printf.printf "not sure what to do with %s\n" (to_string_hum x) ; None
(*      with
        _ -> Printf.printf "failed to parse %s\n" (to_string_hum ele) ; None *)
    in
    match cur with
    | Some x -> x :: acc
    | None -> acc
end

module Cfg = struct
  let cs_mmap file =
    Unix_cstruct.of_fd Unix.(openfile ("/home/hannes/mirage/btc-pinata/ca/" ^ file) [O_RDONLY] 0)

  let priv_cert name =
    let priv = cs_mmap (name ^ ".key")
    and cert = cs_mmap (name ^ ".pem")
    in
    X509.Encoding.Pem.(PrivateKey.of_pem_cstruct1 priv, Cert.of_pem_cstruct1 cert)

  let ca = X509.Encoding.Pem.Cert.of_pem_cstruct1 (cs_mmap "cacert.pem")

  let authenticator =
    X509.Authenticator.chain_of_trust ~time:(Unix.gettimeofday ()) [ca]

  let client_config =
    let priv, cert = priv_cert "client" in
    Config.({ default_config with own_certificates = `Single ([cert ; ca], priv) ; authenticator = Some authenticator })

  let server_config =
    let priv, cert = priv_cert "server" in
    Config.({ default_config with own_certificates = `Single ([cert ; ca], priv) ; authenticator = Some authenticator })
end

type stats = {
  empty : int ;
  fails : int ;
  client : int ;
  server : int ;
  rev_client : int ;
  timeout : int ;
  aborted : int ;
  web_access : string list ;
  tls_access : string list ;
}

let empty_stat =
  { empty = 0 ; fails = 0 ;
    client = 0 ; server = 0 ; rev_client = 0 ;
    timeout = 0 ; aborted = 0 ;
    web_access = [] ; tls_access = [] ;
  }

let client_sccs_fix xs =
  let open Sexplib.Sexp in
  List.iter (function | List [ Atom "state-out" ; List so ] ->
      List.iter (function | List [ Atom "handshake" ; List hs ] ->
          List.iter (function | List [ Atom "machina" ; m ] ->
              (match m with
               | List [ Atom "Client" ; List s ] ->
                 List.iter (function Atom "AwaitServerChangeCipherSpec" ->
                     (try let _ = Reader.conv_hs Cfg.client_config (List hs) in ()
                      with _ -> ())
                                   | s -> ()) s
               | m -> ())
                              | ele -> ()) hs
                          | _ -> ()) so
                      | _ -> ()) xs

let stats = Hashtbl.create 100
let web_users = Hashtbl.create 100
let web_tls_users = Hashtbl.create 100
let tls_users = Hashtbl.create 100

let print_stats statistics =
  Printf.printf "%d failures %d timeout %d aborted %d empty\n"
    statistics.fails statistics.timeout statistics.aborted statistics.empty ;
  Printf.printf "%d client %d rev-client %d server\n%!"
    statistics.client statistics.rev_client statistics.server ;
  Printf.printf "unique web users: %d\n" (Hashtbl.length web_users) ;
  Printf.printf "unique web tls users: %d\n" (Hashtbl.length web_tls_users) ;
  Printf.printf "unique tls users: %d\n" (Hashtbl.length tls_users) ;
  Printf.printf "buf in: %d\n" (Hashtbl.length Reader.buf_in_table) ;
(*  Hashtbl.iter (fun k v ->
      Printf.printf "%d: %s web\n" v k)
    web_users ;
  Hashtbl.iter (fun k v ->
      Printf.printf "%d: %s tls\n" v k)
    tls_users ; *)
(*  let bufs = Hashtbl.fold (fun k v acc ->
      if String.length k < 6 || String.sub k 0 5 <> "GET /" then
        (v, k) :: acc
      else
        acc)
      Reader.buf_in_table [] in
  let bufs = List.sort (fun (v1, _) (v2, _) -> compare v2 v1) bufs in
  List.iter (fun (v, k) -> Printf.printf "%d: %s\n" v k) bufs ;
*)
  let num_traces = statistics.client + statistics.rev_client + statistics.server in
  let count = (float_of_int num_traces) /. 100. in
  let values = Hashtbl.fold (fun k v acc -> (v, k) :: acc) stats [] in
  let vals = List.sort (fun (v1, _) (v2, _) -> compare v2 v1) values in
  List.iter (fun (v, k) ->
      Printf.printf "%d (%.2f%%) failure %s\n" v ((float_of_int v) /. count) k)
    vals

let maybe_pem c =
  try Some (X509.Encoding.Pem.Cert.to_pem_cstruct1 c)
  with _ -> None

(* shouldn't be here, stolen from sexp_ext *)
let (h_of_b, b_of_h) =
  let arr = Array.create 256 ""
  and ht  = Hashtbl.create 256 in
  for i = 0 to 255 do
    let str = Printf.sprintf "%02x" i in
    arr.(i) <- str ;
    Hashtbl.add ht str i
  done ;
  (Array.get arr, Hashtbl.find ht)

let to_bytes cs =
  let rec doit = function
    | 0 -> []
    | n -> Char.code (String.get cs (pred n)) :: doit (pred n)
  in
  List.rev (doit (String.length cs))

let count = ref 0
let dump_cert tag c =
  match maybe_pem c with
  | Some cert ->
    let open Unix in
    let filename = Printf.sprintf "%03d-%s.pem" !count tag in
    count := succ !count;
    let hex = String.concat "" (List.map h_of_b (to_bytes (X509.id c))) in
    let certname = "cert-" ^ hex ^ ".pem" in
    (try
      access certname [ F_OK ]
     with Unix_error _ ->
       let fd = openfile certname [ O_WRONLY ; O_TRUNC ; O_CREAT ] 0o600 in
       let _ = write fd (Cstruct.to_string cert) 0 (Cstruct.len cert) in
       close fd ) ;
    (try
      access filename [ F_OK ]
     with Unix_error _ ->
       symlink certname filename)
  | None -> Printf.printf "couldn't pem cert\n"

let f_to_s = function
  | `Fatal (`UnexpectedHandshake _) -> "unexpected handshake"
  | `Fatal (`UnknownRecordVersion _) -> "unknown record version"
  | `Fatal (`NoCiphersuite _) -> "no shared cipher"
  | `Fatal (`ReaderError _) -> "parse error"
  | `Error (`AuthenticationFailure (`CertificateExpired c)) -> dump_cert "expired" c ;
    "expired"
  | `Error (`AuthenticationFailure (`SelfSigned c)) -> dump_cert "selfsigned" c ;
    "selfsigned"
  | `Error (`AuthenticationFailure (`InvalidServerExtensions c)) -> dump_cert "server_extension" c ; "invalid server extensions"
  | `Error (`AuthenticationFailure (`InvalidVersion c)) -> dump_cert "version" c ; "invalid version"
  | `Error (`AuthenticationFailure (`InvalidSignature (t, c))) ->
    dump_cert "invalidsig-trust" t ;
    dump_cert "invalidsig-cert" c ;
    "invalid signature"
  | x -> Sexplib.Sexp.to_string_hum (Engine.sexp_of_failure x)

let my_replay tag config trace =
  let st = match tag with
    | "server" -> Engine.server config
    | "client" | "rev-client" -> let st, _ = Engine.client config in st
    | _ -> assert false
  in
  Tracer_replay.replay st st [] (List.rev trace) 0 None false

let process tag config source timestamp trace =
  match
    try
      Some (List.fold_left (Reader.process_sexp config) [] trace)
    with
      _ -> None
  with
  | Some data ->
    if List.length data <> List.length trace then
      Printf.printf "%s %s %d parsed %s trace size -- %d bare\n"
        source timestamp (List.length data) tag (List.length trace) ;
    (match List.hd data with
     | `Failure f ->
       (match tag with
        | "server" ->
          (try
             let _ = my_replay tag config data
             in ()
           with
             _ -> Printf.printf "failed to replay %s %s\n"
                    source timestamp
           (* (Sexplib.Sexp.to_string_hum (Sexplib.Conv.sexp_of_list sexp_of_trace data))) *) )
        | "client" | "rev-client" ->
          (try
             let _ = my_replay tag config data in
             ()
           with
             _ -> Printf.printf "failed to replay client/rev-client %s %s\n"
                    source timestamp
           (* (Sexplib.Sexp.to_string_hum (Sexplib.Conv.sexp_of_list sexp_of_trace data))) *) )
        | _ -> assert false ) ;
       (match f with
        | `Error (`AuthenticationFailure `NoTrustAnchor)
        | `Fatal `BadCertificateChain ->
          (match
             find_trace
               (function `RecordIn _ -> true | _ -> false)
               data
           with
           | Some (`RecordIn (_, cert)) ->
             (let gotit = ref false in
              match Engine.separate_handshakes cert with
              | State.Ok (xs, _) ->
                (List.iter
                  (fun cert -> match
                      Tls.Reader.parse_handshake cert
                    with
                    | Tls.Reader.Or_error.Ok (Core.Certificate cs) ->
                      gotit := true;
                      let certs = List.map X509.Encoding.parse cs in
                      List.iteri (fun i -> function
                          | Some x ->
                            let tag =
                              Printf.sprintf "%d-%s-%s-chain"
                                i source timestamp
                            in
                            dump_cert tag x
                          | None -> Printf.printf "%s %s x509 encoding failure\n" source timestamp)
                        certs
                    | Tls.Reader.Or_error.Ok _ -> ()
                    | Tls.Reader.Or_error.Error e -> Printf.printf "%s %s failed to parse certificate %s\n" source timestamp (Sexplib.Sexp.to_string_hum (Tls.Reader.sexp_of_error e)))
                  xs) ;
                if not !gotit then
                  Printf.printf "%s %s no certificate found\n" source timestamp
              | _ -> Printf.printf "%s %s separate_handshakes failed\n" source timestamp)
           | _ -> Printf.printf "%s %s couldn't locate record_in\n" source timestamp)
        | _ -> ()
       );
       let k = f_to_s f in
       if Hashtbl.mem stats k then
         Hashtbl.replace stats k (succ (Hashtbl.find stats k))
       else
         Hashtbl.add stats k 1
     | _ ->
       (try
          let _ = my_replay tag config data
          in ()
        with
          _ -> Printf.printf "failed to replay trace\n")) ;
    Some data
  | None -> Printf.printf "failed to process %s trace\n" tag ; None

let read_trace stats kind source timestamp trace =
  Reader.client_ctx := None ; Reader.server_ctx := None ;
  let open Sexplib in
  match
    try Some (Sexp.of_string trace)
    with _ -> None
  with
  | Some (Sexp.List xs) when List.length xs = 0 ->
    { stats with empty = succ stats.empty }
  | Some (Sexp.List xs) ->
    (match kind with
     | "server" ->
       (match process "server" Cfg.server_config source timestamp xs with
        | Some _ -> { stats with server = succ stats.server }
        | None -> { stats with fails = succ stats.fails } )
     | "client" ->
       (* first locate our cc *)
       client_sccs_fix xs ;
       (match process "client" Cfg.client_config source timestamp xs with
        | Some _ -> { stats with client = succ stats.client }
        | None -> { stats with fails = succ stats.fails } )
     | "rev-client" ->
       client_sccs_fix xs ;
       (match process "rev-client" Cfg.client_config source timestamp xs with
        | Some _ -> { stats with rev_client = succ stats.rev_client }
        | None -> { stats with fails = succ stats.fails } )
     | k ->
       let categorize x =
         match try Some (Conv.string_of_sexp x) with _ -> None with
         | Some s when s = "*TIMEOUT*" ->
           (* we could do something fancy in here... *)
           (* (try
              Printf.printf "before (%d elements) %s\n" (List.length xs) (Sexp.to_string_hum (List.hd (List.tl (List.rev xs)))) ;
              Printf.printf "full trace %s\n" (Sexp.to_string_hum (Sexp.List xs))
              with _ -> ()) ; *)
           { stats with timeout = succ stats.timeout }
         | Some s when s = "*ABORTED*" ->
           { stats with aborted = succ stats.aborted }
         | _ ->
           { stats with fails = succ stats.fails }
       in
       categorize List.(hd (rev xs))
    )
  | _ ->
    { stats with fails = succ stats.fails }

let load_file stats file =
  let chan =
    let fd = Unix.openfile file [ Unix.O_RDONLY ] 0o600 in
    Unix.in_channel_of_descr fd
  in
  let find_tag str =
    let start = succ (String.index str '[')
    and stop = String.index str ']'
    in
    (String.sub str start (stop - start), succ (succ stop))
  in
  let ts_to_string ts =
    let fl = Scanf.sscanf ts "%.05f" (fun x -> x) in
    let tm = Unix.gmtime fl in
    if tm.Unix.tm_mon > 1 || (tm.Unix.tm_mon = 1 && tm.Unix.tm_mday > 9) then
      Some (Printf.sprintf "%d" (int_of_float fl))
    else
      None
  in
  let rec readl tbl stats =
    match
      try Some (input_line chan) with End_of_file -> Unix.close (Unix.descr_of_in_channel chan) ; None
    with
    | Some line ->
      (* we read a line, try to find its kind, and add it to the hashtables (stats and attribution of the trace *)
      let stats' =
        let next_c c fr = String.index_from line fr c in
        let next_ws = next_c ' ' in
        (match
           try
             (* Printf.printf "start parsing line\n"; *)
             let tag, source_start = find_tag line in
             (* Printf.printf "tag is %s\n" tag ; *)
             let source_stop = (next_c ':') source_start in
             let source = String.sub line source_start (source_stop - source_start) in
             (* Printf.printf "source is %s\n" source ; *)
             let ts_start = succ (next_ws source_start) in
             let ts_stop = next_ws ts_start in
             let ts = String.sub line ts_start (ts_stop - ts_start) in
             (* Printf.printf "ts is %s\n" ts ; *)
             let tr_start = succ ts_stop in
             let tr = String.sub line tr_start (String.length line - tr_start) in
             (* Printf.printf "tr is %s\n" tr ; *)
             Some (tag, source, ts, tr)
           with _ -> None
         with
         | Some ("trace", source, ts, trace) ->
           let kind =
             if Hashtbl.mem tbl source then
               Hashtbl.find tbl source
             else
               "none"
           in
           (* Printf.printf "found a %s trace (s: %s, ts: %s, tr: %d) " kind source ts (String.length trace) ; *)
           read_trace stats kind source ts trace
         | Some ("web", source, ts, _) ->
           (if Hashtbl.mem web_users source then
              Hashtbl.replace web_users source (succ (Hashtbl.find web_users source))
            else
              Hashtbl.add web_users source 1) ;
           (match ts_to_string ts with
            | Some x -> { stats with web_access = x :: stats.web_access }
            | None -> stats)
         | Some ("web-server", source, ts, _) ->
           (if Hashtbl.mem web_tls_users source then
              Hashtbl.replace web_tls_users source (succ (Hashtbl.find web_tls_users source))
            else
              Hashtbl.add web_tls_users source 1) ;
           stats
         | Some (x, source, ts, _) when x = "client" || x = "rev-client" || x = "server" ->
           (if Hashtbl.mem tls_users source then
              Hashtbl.replace tls_users source (succ (Hashtbl.find tls_users source))
            else
              Hashtbl.add tls_users source 1) ;
           Hashtbl.add tbl source x ;
           (match ts_to_string ts with
            | Some x -> { stats with tls_access = x :: stats.tls_access }
            | None -> stats)
         | _ -> { stats with fails = succ stats.fails } )
      in
      readl tbl stats'
    | None -> stats
  in
  let tbl = Hashtbl.create 100 in
  readl tbl stats

let load_dir dir =
  let dirent = Unix.opendir dir in
  let _ = Unix.readdir dirent in
  let _ = Unix.readdir dirent in (* getting rid of . and .. *)
  let filen = ref (try Some (Unix.readdir dirent) with End_of_file -> None) in

  let rec doit stats =
    match !filen with
    | None -> stats
    | Some x ->
      let stats = load_file stats (Filename.concat dir x) in
      (filen := try Some (Unix.readdir dirent) with End_of_file -> None) ;
      doit stats
  in
  doit empty_stat

let dump filename lst =
  let fd = Unix.openfile filename Unix.([ O_WRONLY ; O_TRUNC ; O_CREAT ]) 0o600 in
  List.iter (fun x -> let _ = Unix.write fd (x ^ "\n") 0 11 in ()) lst ;
  Unix.close fd

let run dir file =
  Nocrypto.Rng.reseed (Cstruct.create 1);
  match dir, file with
  | Some dir, _ ->
    let stats = load_dir dir in
    dump "web_access.txt" stats.web_access ;
    dump "tls_access.txt" stats.tls_access ;
    print_stats stats
  | None, Some file ->
    let stats = load_file empty_stat file in
    print_stats stats
  | _ -> assert false


let trace_dir = ref None
let trace_file = ref None
let rest = ref []

let usage = "usage " ^ Sys.argv.(0)

let arglist = [
  ("-f", Arg.String (fun f -> trace_file := Some f), "trace file");
  ("-d", Arg.String (fun d -> trace_dir := Some d), "trace directory");
]

let () =
  Arg.parse arglist (fun x -> rest := x :: !rest) usage ;
  run !trace_dir !trace_file
