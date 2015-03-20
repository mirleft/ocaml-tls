open Read_trace
open Tracer_common

open Tls
open State

(* why this is all so hackish:
  - incomplete traces (hopping sequence numbers of incoming records (after 1 comes 120))
  - incomplete persistency of stream ciphers (we cannot do much after the first handshake)
  - out of order events: state-in; record-in; state-out; record-out -- crucially: in our recorded state, CCS is already encrypted..
  - fragmentation on both levels: record and handshake
  - incomplete traces (such as "()")
  - traces where version in first handshake is not the same as the one in the upcoming (70edd70bfe97ce96 is a great example of this) -- occurs when searching for the next server hello to fill the choices

8 throw exceptions:
90fe96dbbf68e83f -- 01

de46d6f71bc1badb -- bad record mac (as recorded)
d013963be0b88f13 -- bad record mac (as recorded)
--> same ciphersuites, tls 1.0, no one else used same set of ciphers + exts

7da95c2334ae05df -- bad record mac (as recorded)
a9a63b02c10f2020 -- bad record mac (as recorded)
587432efd420d135 -- bad record mac (as recorded)
e307e05290456548 -- bad record mac (as recorded)
--> same ciphersuites, tls 1.2, no one else used same set of ciphers + exts

fd8f542f9e1d1f82 -- master secret is different
 same ciphers+exts by 04ec7b02388d3916 and lots of others..

 ECDHE ciphers!!!
   works again if prepend shared with 00 (is 127 byte, thus making it 128)

APPDATA:
GET / HTTP/1.1
Host: tls.openmirage.org
Connection: Keep-Alive
User-Agent: Mozilla/5.0 ()
Accept-Encoding: gzip,deflate

skipped 380 (reader failed), ignored 2690 (empty or broken trace), failed 8 (see above)

(Alert_in "unknown alert 128") : 143
(Alert_in BAD_CERTIFICATE) : 23
(Alert_in CLOSE_NOTIFY) : 14
(Alert_in PROTOCOL_VERSION) : 29

(Alert_out_different HANDSHAKE_FAILURE UNEXPECTED_MESSAGE) : 7
(Alert_out_different UNEXPECTED_MESSAGE PROTOCOL_VERSION) : 207

(Alert_out_fail BAD_RECORD_MAC) : 48

(End_of_trace 0) : 7476
(End_of_trace 1) : 16050
(End_of_trace 2) : 484
(End_of_trace 3) : 66
(End_of_trace 4) : 11
(End_of_trace 5) : 7
(End_of_trace 7) : 1

(Handle_alert "(Fatal (UnknownRecordVersion (0 0)))") : 2

Alert_out_success : 187
No_handshake_out : 5589
Stream_enc : 5077

code 2015-05-19, data same as above

skipped 1, ignored 2723 failed 10
 --> ignored 368 toosmall 2355
   --> 1 : EmptyDir
       2 : InvalidHmacKey
       365 : (InvalidInitialState Established)

(Alert_in "unknown alert 128") : 143
(Alert_in BAD_CERTIFICATE) : 23
(Alert_in CLOSE_NOTIFY) : 14
(Alert_in PROTOCOL_VERSION) : 29

(Alert_out_different HANDSHAKE_FAILURE UNEXPECTED_MESSAGE) : 7
(Alert_out_different UNEXPECTED_MESSAGE PROTOCOL_VERSION) : 207

(Alert_out_fail BAD_RECORD_MAC) : 48

(End_of_trace 0) : 7478
(End_of_trace 1) : 16297
(End_of_trace 2) : 492
(End_of_trace 3) : 66
(End_of_trace 4) : 11
(End_of_trace 5) : 7
(End_of_trace 7) : 1

(Handle_alert "(Fatal (UnknownRecordVersion (0 0)))") : 2

Alert_out_success : 187
No_handshake_out : 5595
Stream_enc : 5160

 *)

(* pull out initial state *)
let init (trace : trace list) =
  match find_trace (function `StateIn x -> true | _ -> false) trace with
  | Some (`StateIn x) -> x
  | _ -> assert false

let dbg_al al = Sexplib.Sexp.to_string_hum (Core.sexp_of_tls_alert al)

let doit res name ts alert_out trace =
  match alert_out with
  | None ->
    (* Printf.printf "file %s: " name; *)
    let state = init trace in
    let r = Tracer_replay.replay state state [] trace 0 None true in
    if Hashtbl.mem res r then
      let v = Hashtbl.find res r in
      Hashtbl.replace res r (succ v)
    else
      Hashtbl.add res r 1
  | Some al ->
    let alert = Core.tls_alert_of_sexp al in
    (* these are the traces ending with an AlertOut! *)
    let state = init trace in
    let r = Tracer_replay.replay state state [] trace 0 (Some alert) true in
    if Hashtbl.mem res r then
      let v = Hashtbl.find res r in
      Hashtbl.replace res r (succ v)
    else
      Hashtbl.add res r 1

let analyse_res r =
  Hashtbl.iter (fun k v ->
      Printf.printf "%s : %d\n" (Sexplib.Sexp.to_string_hum (Tracer_replay.sexp_of_ret k)) v)
    r

let run dir file =
  Nocrypto.Rng.reseed (Cstruct.create 1);
  match dir, file with
  | Some dir, _ ->
    let res = Hashtbl.create 10 in
    let toosmall = ref 0
    and failed = ref 0
    and ign = ref 0
    and ignored = Hashtbl.create 10
    in
    let suc (name, (ts, (alert, traces))) =
      try (
        if List.length traces > 2 then
          (Printf.printf "+%!" ;
           doit res name ts alert traces)
        else
          toosmall := succ !toosmall )
      with e -> Printf.printf "%s error: %s\n%!" name (Printexc.to_string e) ; failed := succ !failed
    and fail (_, e) =
      let msg = Sexplib.Sexp.to_string_hum (sexp_of_read_error e) in
      ign := succ !ign ;
      if Hashtbl.mem ignored msg then
        let v = Hashtbl.find ignored msg in
        Hashtbl.replace ignored msg (succ v)
      else
        Hashtbl.add ignored msg 1
    in
    let skip = load_dir dir suc fail in
    Printf.printf "\nskipped %d, ignored %d toosmall %d failed %d\n" skip !ign !toosmall !failed;
    (* Hashtbl.iter (fun k v -> Printf.printf "%d : %s\n" v k) ignored ; *)
    analyse_res res
  | None, Some file ->
    let ts, (alert, trace) = load file in
    let state = init trace in
    let alert = match alert with
      | None -> None
      | Some x -> Some (Core.tls_alert_of_sexp x)
    in
    let r = Tracer_replay.replay state state [] trace 0 alert true in
    Printf.printf "result %s\n" (Sexplib.Sexp.to_string_hum (Tracer_replay.sexp_of_ret r))
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
