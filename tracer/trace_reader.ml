open Read_trace
open Tracer_common

open Tls
open State

type result = [
  | `UserAgent of string
  | `Referer of string
]

let result_to_string = function
  | `UserAgent s -> "user-agent: " ^ s
  | `Referer r -> "referer: " ^ r

let user_agent =  "User-Agent: "
let referer = "Referer: "

let find_user_agent buf =
  let str = Cstruct.to_string buf in
  let find_string on =
    try
      match Stringext.cut str ~on with
      | Some (_, data) ->
        let nl = try String.index data '\r' with Not_found -> String.length data in
        Some (String.sub data 0 nl)
      | _ -> None
    with
      _ -> None
  in
  find_string user_agent

let rec analyse acc = function
  | (`ApplicationDataIn s)::xs -> analyse (s :: acc) xs
  | _::xs -> analyse acc xs
  | [] -> List.rev acc

let rec find_trace (p : trace -> bool) (xs : trace list) =
  match xs with
  | [] -> None
  | x::_ when p x -> Some x
  | _::xs -> find_trace p xs

let rec unique acc = function
  | [] -> acc
  | x::xs when List.mem x acc -> unique acc xs
  | x::xs -> unique (x :: acc) xs

let count_unique xs =
  let data = Hashtbl.create (List.length xs) in
  List.iter (fun x ->
      if Hashtbl.mem data x then
        let ele = Hashtbl.find data x in
        Hashtbl.replace data x (succ ele)
      else
        Hashtbl.add data x 1) xs ;
  Hashtbl.fold (fun k v acc ->
      (k, v) :: acc)
    data []

let analyse_ua trace =
  let appdata = analyse [] trace in
  find_user_agent (Nocrypto.Uncommon.Cs.concat appdata)


let analyse_trace name trace =
  let server_hello =
    let tst data = Cstruct.len data > 0 && Cstruct.get_uint8 data 0 = 2 in
    let sh = find_trace (function `RecordOut (Packet.HANDSHAKE, d) when tst d -> true | _ -> false) trace in
    match sh with
    | Some (`RecordOut (_, sh)) ->
      (match Reader.parse_handshake_frame sh with
       | None, _ -> assert false
       | Some data, _ -> Reader.parse_handshake data)
    | _ -> assert false
  in
  let appdata = analyse [] trace in
  let ua = find_user_agent (Nocrypto.Uncommon.Cs.concat appdata) in
  match server_hello with
  | Reader.Or_error.Ok Core.ServerHello sh ->
    Some (sh.Core.version, sh.Core.ciphersuites, ua)
  | _ -> Printf.printf "problem while parsing sth in %s\n" name ; None

let analyse_success hashtbl =
  (* key is name, value is (timestamp, trace) *)
  let stats, uas =
    Hashtbl.fold (fun name (_, trace) (s, ua) ->
        match analyse_trace name trace with
        | Some (v, c, u) -> ((v, c) :: s, u :: ua)
        | None -> (s, ua))
      hashtbl ([], [])
  in
  let s_stats = Hashtbl.create 9 in
  let sua = List.combine stats uas in
  List.iter (fun (s, ua) ->
      if Hashtbl.mem s_stats s then
        let cnt, uas = Hashtbl.find s_stats s in
        let uas = if List.mem ua uas then uas else ua :: uas in
        Hashtbl.replace s_stats s (succ cnt, uas)
      else
        Hashtbl.add s_stats s (1, [ua])) sua ;
  Hashtbl.iter (fun (ver, cip) (v, ua) ->
      Printf.printf "%d %s %s used by %d\n"
        v
        (Printer.tls_version_to_string ver)
        (Ciphersuite.ciphersuite_to_string cip)
        (List.length (Utils.filter_map ~f:(fun x -> x) ua)))
    s_stats ;
  let uas = Hashtbl.fold (fun k (_, uas) acc ->
      let rec maybe_add ac xs =
        match xs with
        | [] -> ac
        | None::xs -> maybe_add ac xs
        | (Some x)::xs when List.mem x ac -> maybe_add ac xs
        | (Some x)::xs -> maybe_add (x :: ac) xs
      in
      maybe_add acc uas) s_stats []
  in
  Printf.printf "%d disjoint user-agents\n  %s\n" (List.length uas) (String.concat "\n  " uas)

let analyse_reneg t =
  List.length (List.filter (function `HelloRequest -> true | _ -> false) t)

let analyse_renegs hashtbl =
  let renegs =
    Hashtbl.fold (fun n (_, trace) rs ->
        analyse_reneg trace :: rs)
      hashtbl []
  in
  let rs = count_unique renegs in
  Printf.printf "renegs:\n  %s\n"
    (String.concat "\n  " (List.map (fun (renegcount, tracecount) ->
         (string_of_int renegcount) ^ ": " ^ (string_of_int tracecount))
         (List.sort (fun (a, _) (b, _) -> compare a b) rs)))

let analyse_protocol_version trace =
  let client_hello =
    let tst data = Cstruct.len data > 0 && Cstruct.get_uint8 data 0 = 1 in
    let ch = find_trace (function `RecordIn (hdr, data) -> hdr.Core.content_type = Packet.HANDSHAKE && tst data | _ -> false) trace in
    match ch with
    | Some (`RecordIn (_, ch)) -> Reader.parse_handshake ch
    | _ -> assert false
  in
  match client_hello with
  | Reader.Or_error.Ok Core.ClientHello ch -> ch.Core.version
  | _ -> assert false

let null_cs c =
  let open Packet in
  match c with
  | TLS_NULL_WITH_NULL_NULL
  | TLS_RSA_WITH_NULL_MD5
  | TLS_RSA_WITH_NULL_SHA
  | RESERVED_SSL3_1
  | RESERVED_SSL3_2
  | TLS_PSK_WITH_NULL_SHA
  | TLS_DHE_PSK_WITH_NULL_SHA
  | TLS_RSA_PSK_WITH_NULL_SHA
  | TLS_RSA_WITH_NULL_SHA256
  | TLS_PSK_WITH_NULL_SHA256
  | TLS_PSK_WITH_NULL_SHA384
  | TLS_DHE_PSK_WITH_NULL_SHA256
  | TLS_DHE_PSK_WITH_NULL_SHA384
  | TLS_RSA_PSK_WITH_NULL_SHA256
  | TLS_RSA_PSK_WITH_NULL_SHA384
  | TLS_ECDH_ECDSA_WITH_NULL_SHA
  | TLS_ECDHE_ECDSA_WITH_NULL_SHA
  | TLS_ECDH_RSA_WITH_NULL_SHA
  | TLS_ECDHE_RSA_WITH_NULL_SHA
  | TLS_ECDH_anon_WITH_NULL_SHA
  | TLS_ECDHE_PSK_WITH_NULL_SHA
  | TLS_ECDHE_PSK_WITH_NULL_SHA256
  | TLS_ECDHE_PSK_WITH_NULL_SHA384 -> true
  | _ -> false

type f = [
  | `Failure of Tls.Engine.failure
  | `DuplicatedCamellia
  | `DuplicatedEcdheAes128
  | `NullProposed
  | `NoCipher
  | `NoCipherYet
] with sexp

let analyse_alerts hashtbl =
  (* err -> (timestamp, name, traces) *)
  let version_fails =
    Hashtbl.find hashtbl (Core.sexp_of_tls_alert (Packet.FATAL, Packet.PROTOCOL_VERSION))
  in
  let versions = List.map analyse_protocol_version (List.map (fun (_, _, x) -> x) version_fails) in
  let name_versions = List.combine version_fails versions in
  let unsupported = List.filter (fun (_, v) -> match v with
      | Core.SSL_3 -> true
      | Core.TLS_1_X _ -> true
      | _ -> false) name_versions
  in
  let single = unique [] (List.map snd unsupported) in
  Printf.printf "%d unsupported versions: %s\n"
    (List.length unsupported)
    (String.concat ", " (List.map Printer.tls_any_version_to_string single)) ;
  let supported = List.filter (fun (_, v) -> match v with
      | Core.Supported v -> true
      | _ -> false) name_versions
  in
  let sup_len = unique [] (List.map List.length (List.map (fun ((_, _, t), _) -> t) supported)) in
  Printf.printf "%d supported versions (other failure) %s\n" (List.length supported) (String.concat ", " (List.map string_of_int sup_len)) ;

  let unexpected =
    Hashtbl.find hashtbl (Core.sexp_of_tls_alert (Packet.FATAL, Packet.UNEXPECTED_MESSAGE))
  in
  let unexpected_traces = List.map (fun (_, _, x) -> x) unexpected in
  let find_hs_state t =
    match
      find_trace (function `State _ -> true | `StateIn _ -> true | `StateOut _ -> true | _ -> false) (List.rev t)
    with
    | Some (`State x) | Some (`StateIn x) | Some (`StateOut x) ->
      (match x.handshake.machina with
       | Server AwaitClientHello -> "await client hello"
       | Server AwaitClientHelloRenegotiate -> "await client hello renegotiate"
       | Server (AwaitClientCertificate_RSA _) -> "await client certificate RSA"
       | Server (AwaitClientCertificate_DHE_RSA _) -> "await client certificate DHE_RSA"
       | Server (AwaitClientKeyExchange_RSA _) -> "await client key exchange RSA"
       | Server (AwaitClientKeyExchange_DHE_RSA _) -> "await client key exchange DHE_RSA"
       | Server (AwaitClientCertificateVerify _) -> "await client certificate verify"
       | Server (AwaitClientChangeCipherSpec _) -> "await client change cipher spec"
       | Server (AwaitClientFinished _) -> "await client finished"
       | Server Established -> "established"
       | _ -> assert false )
    | _ -> assert false
  in
  let find_record_in (ts, name, t) =
    match
      find_trace (function `RecordIn _ -> true | _ -> false) (List.rev t)
    with
    | Some (`RecordIn (hdr, data)) ->
      (let open Packet in
       let open Reader in
       match hdr.Core.content_type with
       | CHANGE_CIPHER_SPEC -> (* Printf.printf "%s ccs\n" ts ; *) "CCS"
       | ALERT ->
         ( match parse_alert data with
           | Or_error.Ok (lvl, typ) ->
             (alert_level_to_string lvl) ^ ", " ^ (alert_type_to_string typ)
           | _ -> Printf.sprintf "unknown alert %02x %02x"
                    (Cstruct.get_uint8 data 0) (Cstruct.get_uint8 data 1) )
       | HANDSHAKE ->
         ( match parse_handshake data with
           | Or_error.Ok hs -> Printer.handshake_to_string hs
           | Or_error.Error (TrailingBytes x) ->
             Printf.sprintf "handshake %02x trailing bytes %s"
               (Cstruct.get_uint8 data 0) x
           | Or_error.Error (Unknown x) ->
             Printf.sprintf "handshake %02x unknown %s"
               (Cstruct.get_uint8 data 0) x
           | Or_error.Error (WrongLength x) ->
             Printf.sprintf "handshake %02x wrong length %s"
               (Cstruct.get_uint8 data 0) x
           | Or_error.Error Underflow ->
             Printf.sprintf "handshake %02x underflow"
               (Cstruct.get_uint8 data 0) )
       | _ -> "unknown content" )
    | _ -> assert false
  in
  let last_state = List.map find_hs_state unexpected_traces in
  let last_record = List.map find_record_in unexpected in
  let lsu = count_unique (List.combine last_state last_record) in
  Printf.printf "%d unexpected\n%s\n"
    (List.length last_state)
    (String.concat "\n" (List.map (fun ((a, b), c) ->
         (string_of_int c) ^ ": state: " ^ a ^ ", content type: " ^ b)
         lsu)) ;

  let failed =
    Hashtbl.find hashtbl (Core.sexp_of_tls_alert (Packet.FATAL, Packet.HANDSHAKE_FAILURE))
  in

  (* replay them for more detailed error message *)
  let err (_, n, t) =
    let client_hello t =
      let tst data = Cstruct.len data > 0 && Cstruct.get_uint8 data 0 = 1 in
      match
        find_trace (function `RecordIn (hdr, data) -> hdr.Core.content_type = Packet.HANDSHAKE && tst data | _ -> false) t
      with
      | Some (`RecordIn (hdr, data)) -> (hdr, data)
      | _ -> assert false
    in

    let state t =
      match
        find_trace (function `StateIn _ -> true | _ -> false) t
      with
      | Some (`StateIn x) -> x
      | _ -> assert false
    in

    let in_state = state t
    and ch = client_hello t
    in
    let extract_ch b =
      match Reader.parse_handshake (snd b) with
      | Reader.Or_error.Ok (Core.ClientHello ch) -> ch
      | _ -> assert false
    in
    match Engine.handle_tls in_state (fixup_in_record (fst ch) (snd ch)) with
    | `Ok (`Ok st, `Response _, `Data _) ->
      let ch = extract_ch ch in
      if List.exists null_cs ch.Core.ciphersuites then
        Some `NullProposed
      else
        (Printf.printf "nothing wrong in %s\n" n ; None)
    | `Ok _ -> Printf.printf "seems all good to me\n" ; None
    | `Fail ((`Fatal `InvalidClientHello), _) ->
      let ch = extract_ch ch in
      if List.length (List.filter (function Packet.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 -> true | _ -> false) ch.Core.ciphersuites) > 1 then
        Some `DuplicatedCamellia
      else if List.length (List.filter (function Packet.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -> true | _ -> false) ch.Core.ciphersuites) > 1 then
        Some `DuplicatedEcdheAes128
      else
        (Printf.printf "client hello invalid in %s\n" n;  Some (`Failure (`Fatal `InvalidClientHello)))
    | `Fail ((`Fatal (`NoCiphersuite _)), _) -> Some `NoCipher
    | `Fail ((`Error (`NoConfiguredCiphersuite _)), _) -> Some `NoCipherYet
    | `Fail ((`Fatal `InvalidRenegotiation), _) ->
      Printf.printf "invalid renegotiation %s\n" n ;
      Some (`Failure (`Fatal `InvalidRenegotiation))
    | `Fail (x, _) -> Some (`Failure x)

  in

  let errs = List.map err failed in
  let trace_len = count_unique errs in
  Printf.printf "%d handshake failure:\n%s\n"
    (List.length failed) (String.concat "\n" (List.map (fun (err, cnt) ->
        let v = match err with None -> "none" | Some x -> Sexplib.Sexp.to_string_hum (sexp_of_f x) in
        (string_of_int cnt) ^ " times " ^ v)
        trace_len))


let run dir file read =
  Nocrypto.Rng.reseed (Cstruct.create 10);
  match dir, file, read with
  | Some dir, _, _ ->
    let successes = Hashtbl.create 100
    and alerts = Hashtbl.create 100
    and early_alerts = Hashtbl.create 100
    and alert_in = Hashtbl.create 100
    and failures = Hashtbl.create 100
    in
    let suc (name, (ts, (alert, (traces : trace list)))) =
      let len = List.length traces in
      if List.exists (function `AlertIn x -> true | _ -> false) traces then
        let alert = List.filter (function `AlertIn x -> true | _ -> false) traces in
        assert (List.length alert = 1) ;
        let x = match alert with
          | [`AlertIn x] -> x
          | _ -> assert false
        in
        let x = Core.sexp_of_tls_alert x in
        if Hashtbl.mem alert_in x then
          let ele = Hashtbl.find alert_in x in
          Hashtbl.replace alert_in x ((ts, name) :: ele)
        else
          Hashtbl.add alert_in x [(ts, name)]
      else
      match alert with
      | None ->
        if len < 10 then
          (* Printf.printf "%d elements - broken non-alert trace at %s ?\n" len name *)
          ()
        else if Hashtbl.mem successes name then
          (* let ele = Hashtbl.find successes name in
             Hashtbl.replace successes name ele *)
          assert false
        else
          Hashtbl.add successes name (ts, traces)
      | Some x ->
        if len < 3 then
          if Hashtbl.mem early_alerts x then
            let ele = Hashtbl.find early_alerts x in
            Hashtbl.replace early_alerts x ((ts, name) :: ele)
          else
            Hashtbl.add early_alerts x [(ts, name)]
        else if Hashtbl.mem alerts x then
          let ele = Hashtbl.find alerts x in
          Hashtbl.replace alerts x ((ts, name, traces) :: ele)
        else
          Hashtbl.add alerts x [(ts, name, traces)]
    and fails (name, e) =
      if Hashtbl.mem failures e then
        let ele = Hashtbl.find failures e in
        Hashtbl.replace failures e (name :: ele)
      else
        Hashtbl.add failures e [name]
    in

    let skip = load_dir dir suc fails in
    Printf.printf "skipped %d\n" skip ;

    Printf.printf "success size %d\n" (Hashtbl.length successes) ;
(*    Hashtbl.iter (fun k (ts, trace) ->
        Printf.printf "success trace length %d count %d\n" k v)
      successes ; *)
    Hashtbl.iter (fun k v ->
        Printf.printf "alert in %s count %d\n" (Sexplib.Sexp.to_string_hum k) (List.length v))
      alert_in ;
    Hashtbl.iter (fun k v ->
        Printf.printf "alert %s count %d\n" (Sexplib.Sexp.to_string_hum k) (List.length v))
      alerts ;
    Hashtbl.iter (fun k v ->
        Printf.printf "early alert %s count %d\n" (Sexplib.Sexp.to_string_hum k) (List.length v))
      early_alerts ;
    analyse_alerts alerts ;
    analyse_success successes ;
    analyse_renegs successes ;
    Hashtbl.iter (fun k v ->
        Printf.printf "reason %s count %d\n" (Sexplib.Sexp.to_string_hum (sexp_of_read_error k)) (List.length v))
      failures

  | None, Some file, _ ->
    (try (let ts, (alert, traces) = load file in
          match alert with
          | Some alert ->
            Printf.printf "trace from %s, alert %s (%d traces)\n"
              ts (Sexplib.Sexp.to_string_hum alert) (List.length traces)
          | None ->
            Printf.printf "trace from %s, loaded %d traces\n" ts (List.length traces) ;
            let hash = Hashtbl.create 1 in
            Hashtbl.add hash file (ts, traces) ;
            analyse_success hash)
     with
       Trace_error e -> Printf.printf "problem %s\n" (Sexplib.Sexp.to_string_hum (sexp_of_read_error e)))
  | None, None, Some r ->
    let chan = open_in r in
    let rec collect () =
      try
        let item = input_line chan in
        let rest = collect () in
        item :: rest
      with
        End_of_file -> []
    in
    let acc = collect () in
    close_in chan ;
    let path = Filename.dirname r in
    let traces = List.fold_left (fun acc f ->
        let file = Filename.concat path (Filename.dirname f) in
        (try let ts, (alert, traces) = load file in
           match alert with
           | Some alert ->
             Printf.printf "trace from %s, alert %s (%d traces)\n"
               ts (Sexplib.Sexp.to_string_hum alert) (List.length traces);
             acc
           | None -> traces :: acc
         with
           Trace_error e -> Printf.printf "problem %s\n" (Sexplib.Sexp.to_string_hum (sexp_of_read_error e)) ; acc)) [] acc
    in
    let uas = Hashtbl.create 7 in
    List.iter (fun t ->
        let ua = match analyse_ua t with
          | Some ua -> ua
          | None -> "none"
        in
        if Hashtbl.mem uas ua then
          Hashtbl.replace uas ua (succ (Hashtbl.find uas ua))
        else
          Hashtbl.add uas ua 1) traces;
    Hashtbl.iter (fun k v ->
        Printf.printf "%d ua %s\n" v k)
      uas
  | _ -> assert false


let trace_dir = ref None
let trace_file = ref None
let trace_read = ref None
let rest = ref []

let usage = "usage " ^ Sys.argv.(0)

let arglist = [
  ("-f", Arg.String (fun f -> trace_file := Some f), "trace file");
  ("-d", Arg.String (fun d -> trace_dir := Some d), "trace directory");
  ("-r", Arg.String (fun r -> trace_read := Some r), "trace from file list");
]

let () =
  Arg.parse arglist (fun x -> rest := x :: !rest) usage ;
  run !trace_dir !trace_file !trace_read
