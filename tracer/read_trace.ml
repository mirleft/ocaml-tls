(* reading traces back in from those created in TLS *)

open Sexplib
open Sexplib.Sexp
open Sexplib.Conv

open Tracer_common

open Tls

(* why is this so messy? because tls-0.1.0 (which we used to produce traces) uses
   different data types! Also, the trace is only partial (esp cipher_state is not
   marshalled to disk). In here, we only read those traces (and make them complete!). *)

(* we currently focus on traces recorded by the server, thus some partial pattern matches
   (don't expect this to work for a client trace) *)

(* since record-out is emitted after state-out, we install encryptor before record-out ccs *)

(* since cipher_st is only partially marshaled, we treat it carefully (and recompute the ctx
   for AwaitClientChangeCipherSpec), installing them on change-cipher-spec-out *)

(* we also preserve session_data from the current handshake when we
   sent out Finished (handshake-out Finished below), data structure
   (of 0.3) has a session list in the handshake_state record *)

module Cstruct_s = struct

  type t = Cstruct.t

  let (h_of_b, b_of_h) =
    let arr = Array.create 256 ""
    and ht  = Hashtbl.create 256 in
    for i = 0 to 255 do
      let str = Printf.sprintf "%02x" i in
      arr.(i) <- str ;
      Hashtbl.add ht str i
    done ;
    (Array.get arr, Hashtbl.find ht)

  let t_of_sexp sexp =

    let failure msg sexp =
      Conv.of_sexp_error ("Cstruct_s.t_of_sexp: " ^ msg ^ " needed") sexp in

    let rec measure a = function
      | Atom _  -> a + 1
      | List xs -> List.fold_left measure a xs

    and write i cs l1 = function
      | (Atom str as sexp)::l2 ->
          let b =
            try b_of_h str with Not_found -> failure "hex byte" sexp in
          Cstruct.set_uint8 cs i b ;
          write (succ i) cs l1 l2
      | sexp :: _ -> failure "atom" sexp
      | []        ->
          match l1 with
          | List l2::l1' -> write i cs l1' l2
          | sexp   ::_   -> failure "inner list" sexp
          | []           -> ()
    in
    match sexp with
    | Atom _           -> failure "list" sexp
    | List list as exp ->
        let cs = Cstruct.create (measure 0 exp) in
        ( write 0 cs list [] ; cs )


  let cs_fold_bytes ~f ~init cs =
    let acc = ref init in
    for i = 0 to Cstruct.len cs - 1 do
      acc := f !acc i Cstruct.(get_uint8 cs i)
    done ;
    !acc

  let sexp_of_t cs =
    let of_list list = List (List.rev list) in
    let append big = function
      | []    -> big
      | small -> of_list small :: big in
    let (l1, l2) =
      cs_fold_bytes
      ~f:(fun (l1, l2 as acc) i b ->
          let (l1, l2) =
            if i mod 16 = 0 then
              (append l1 l2, [])
            else acc in
          (l1, Atom (h_of_b b) :: l2))
      ~init:([], [])
      cs in
    of_list @@ append l1 l2

end

let parse_cstruct = function
  | List data -> Cstruct_s.t_of_sexp (List data)
  | Atom data -> Cstruct.t_of_sexp (Atom data)

let parse_log = function
  | List ls -> List.map parse_cstruct ls
  | Atom _ -> assert false

type read_error =
  | InvalidInitialState of string
  | InvalidHmacKey
  | InvalidSequenceNumber
  | InvalidCipherState
  | InvalidVersion
  | InvalidIv
  | EmptyDir
with sexp

exception Trace_error of read_error

let fail e = raise (Trace_error e)

let guard exp e = if exp then () else fail e

let session_of_server s =
  let open State in
  match s with
  | AwaitClientHello -> None
  | AwaitClientHelloRenegotiate -> None
  | AwaitClientCertificate_RSA (session_data, _) -> Some session_data
  | AwaitClientCertificate_DHE_RSA (session_data, _, _) -> Some session_data
  | AwaitClientKeyExchange_RSA (session_data, _) -> Some session_data
  | AwaitClientKeyExchange_DHE_RSA (session_data, _, _) -> Some session_data
  | AwaitClientCertificateVerify (session_data, _, _, _) -> Some session_data
  | AwaitClientChangeCipherSpec (session_data, _, _, _) -> Some session_data
  | AwaitClientFinished (session_data, _) -> Some session_data
  | Established -> None

let session_of_state = function
  | State.Server x -> session_of_server x
  | _              -> None

let session = function
  | None -> Handshake_common.empty_session
  | Some x -> match session_of_state x.State.handshake.State.machina with
    | None -> Handshake_common.empty_session
    | Some x -> x

let version = function
  | None -> Core.TLS_1_0
  | Some x -> x.State.handshake.State.protocol_version

type tls_ver =
    SSL_3 | TLS_1_0 | TLS_1_1 | TLS_1_2 | TLS_1_X of (int * int) with sexp

let tls_ver_to_any_version = function
  | SSL_3 -> Core.SSL_3
  | TLS_1_0 -> Core.(Supported TLS_1_0)
  | TLS_1_1 -> Core.(Supported TLS_1_1)
  | TLS_1_2 -> Core.(Supported TLS_1_2)
  | TLS_1_X (3, m) -> Core.TLS_1_X m
  | TLS_1_X _ -> fail InvalidVersion

type rec_out = Packet.content_type * Cstruct_s.t with sexp

type hs_params = {
  server_random  : Cstruct_s.t ;
  client_random  : Cstruct_s.t ;
  client_version : tls_ver ;
  cipher         : Ciphersuite.ciphersuite
} with sexp

let conv_hs_params sess data =
  let hs_params = hs_params_of_sexp data in
  { sess with
    State.server_random = hs_params.server_random ;
    State.client_random = hs_params.client_random ;
    State.client_version = tls_ver_to_any_version hs_params.client_version ;
    State.ciphersuite = hs_params.cipher }

type cs =
  | Random
  | Iv of Cstruct_s.t
  | Stream

let sexp_of_old_cs = function
  | List [ Atom "<cbc-state>" ; Atom "Random_iv" ] -> Random
  | List [ Atom "<cbc-state>" ; List [ Atom "Iv" ; iv ] ] -> Iv (Cstruct_s.t_of_sexp iv)
  | Atom "<stream-state>" -> Stream
  | _ -> assert false

let sexp_of_old_cc s =
  match
    List.fold_left (fun (seq, cipher, mac) -> function
        | List [ Atom "sequence" ; seq ] -> (Some (int64_of_sexp seq), cipher, mac)
        | List [ Atom "cipher_st" ; cs ] -> (seq, Some (sexp_of_old_cs cs), mac)
        | List [ Atom "mac" ; mac ] -> (seq, cipher, Some (Cstruct_s.t_of_sexp mac))
        | _ -> assert false
      ) (None, None, None) s
  with
  | Some s, Some c, Some m -> (s, c, m)
  | _ -> assert false

let sexp_of_old_cc_option = function
  | List [] -> None
  | List [ List xs ] -> Some (sexp_of_old_cc xs)
  | _ -> assert false

let cc_checker old_cc new_cc =
  let sequence, iv, mac = sexp_of_old_cc old_cc in
  guard (new_cc.State.sequence = sequence) InvalidSequenceNumber;
  match new_cc.State.cipher_st with
  | State.Stream s ->
    guard (iv = Stream) InvalidCipherState ;
    guard (Nocrypto.Uncommon.Cs.equal s.State.hmac_secret mac) InvalidHmacKey
  | State.CCM _ -> assert false (* demo server didn't have this! *)
  | State.CBC c ->
    guard (Nocrypto.Uncommon.Cs.equal c.State.hmac_secret mac) InvalidHmacKey ;
    match c.State.iv_mode, iv with
    | State.Iv x, Iv y -> guard (Nocrypto.Uncommon.Cs.equal x y) InvalidIv
    | State.Random_iv, Random -> ()
    | _ -> fail InvalidCipherState

let conv_server_handshake maybe_state = function
  | Atom "ServerInitial" | Atom "AwaitClientHello" -> State.AwaitClientHello
  | List [ Atom "ServerHelloDoneSent_DHE_RSA" ; hs ; dh ; log ]
  | List [ Atom "AwaitClientKeyExchange_DHE_RSA" ; hs ; dh ; log ] ->
    guard (maybe_state <> None) (InvalidInitialState "AwaitClientKeyExchange_DHE_RSA") ;
    let session_data = session maybe_state in
    let sess = conv_hs_params session_data hs in
    State.AwaitClientKeyExchange_DHE_RSA (sess, State.dh_sent_of_sexp dh, parse_log log)
  | List [ Atom "ServerHelloDoneSent_RSA" ; hs ; log ]
  | List [ Atom "AwaitClientKeyExchange_RSA" ; hs ; log ] ->
    guard (maybe_state <> None) (InvalidInitialState "AwaitClientKeyExchange_RSA") ;
    let session_data = session maybe_state in
    let sess = conv_hs_params session_data hs in
    State.AwaitClientKeyExchange_RSA (sess, parse_log log)
  | List [ Atom "AwaitChangeCipherSpec" ; List ccc ; List scc ; ms ; log ]
  | List [ Atom "ClientKeyExchangeReceived" ; List ccc ; List scc ; ms ; log ]
  | List [ Atom "AwaitClientChangeCipherSpec" ; List ccc ; List scc ; ms ; log ] ->
    guard (maybe_state <> None) (InvalidInitialState "AwaitClientChangeCipherSpec") ;
    let master_secret = Cstruct_s.t_of_sexp ms in
    let session_data = session maybe_state in
    let session = { session_data with State.master_secret = master_secret } in
    let sc, cc = Handshake_crypto.make_context
        session.State.ciphersuite
        (version maybe_state)
        master_secret
        session.State.server_random
        session.State.client_random
    in
    cc_checker ccc cc ; cc_checker scc sc ;
    State.AwaitClientChangeCipherSpec (session, cc, sc, parse_log log)
  | List [ Atom "AwaitFinished" ; ms ; log ]
  | List [ Atom "ClientChangeCipherSpecReceived" ; ms ; log ]
  | List [ Atom "AwaitClientFinished" ; ms ; log ] ->
    guard (maybe_state <> None) (InvalidInitialState "AwaitClientFinished") ;
    let session = session maybe_state in
    State.AwaitClientFinished (session, parse_log log)
  | Atom "ServerEstablished" | Atom "Established" ->
    guard (maybe_state <> None) (InvalidInitialState "Established") ;
    State.Established
  | _ -> assert false

let conv_machina maybe_state = function
  | List [ Atom "Server" ; xs ] -> State.Server (conv_server_handshake maybe_state xs)
  | _ -> assert false

(* config_of_sexp usually bails out.. *)
(* we implement our own, specialized version *)
let cs_mmap file =
  Unix_cstruct.of_fd Unix.(openfile file [O_RDONLY] 0)

let priv, cert =
  let file = cs_mmap "/home/hannes/tls-certs-mirage/openmirage.pem" in
  (match X509.Encoding.Pem.Private_key.of_pem_cstruct1 file with `RSA k -> k,
   X509.Encoding.Pem.Certificate.of_pem_cstruct file)

let config_of_sexp cfg =
  let open Config in
  (* handling only ciphers, version, hashes *)
  let default = {
    default_config with
      own_certificates = `Single (cert, priv) ;
      authenticator = None
  } in
  match cfg with
  | List l ->
    List.fold_left (fun config -> function
        | List [ Atom "ciphers" ; ciphers ] ->
          let ciphers = list_of_sexp Ciphersuite.ciphersuite_of_sexp ciphers in
          { config with ciphers }
        | List [ Atom "version" ; versions ] ->
          let protocol_versions = pair_of_sexp Core.tls_version_of_sexp Core.tls_version_of_sexp versions in
          { config with protocol_versions }
        | List [ Atom "hashes" ; List hashes ] ->
          let hashes = List (List.map (function Atom "SHA" -> Atom "SHA1" | x -> x) hashes) in
          let hashes = list_of_sexp Nocrypto.Hash.hash_of_sexp hashes in
          { config with hashes }
        | List [ Atom "use_reneg" ; reneg ]
        | List [ Atom "use_rekeying" ; reneg ] ->
          let use_reneg = bool_of_sexp reneg in
          { config with use_reneg }
        | List [ Atom "requre_sec_rek" ; _ ]
        | List [ Atom "secure_reneg" ; _ ]
        | List [ Atom "authenticator" ; _ ]
        | List [ Atom "validator" ; _ ]
        | List [ Atom "certificate" ; _ ]
        | List [ Atom "certificates" ; _ ] ->
          (* ignore, never marshalled to disk anyways *)
          config
        | List [ Atom "peer_name" ; name ] ->
          let peer_name = option_of_sexp string_of_sexp name in
          { config with peer_name }
        | _ -> invalid_arg "error while parsing TLS configuration")
      default l
  | _ -> invalid_arg "error while parsing TLS configuration"

type r_params = Cstruct_s.t * Cstruct_s.t with sexp

let conv_handshake maybe_state = function
  | List eles ->
    begin
      let sessions = match maybe_state with None -> [] | Some x -> x.State.handshake.State.session in
      match
        List.fold_left (fun (session, ver, machina, config, hs_frag) -> function
            | List [ Atom "version" ; x ] -> (session, Some (Core.tls_version_of_sexp x), machina, config, hs_frag)
            | List [ Atom "reneg" ; x ]
            | List [ Atom "rekeying" ; x ] ->
              let sessions = match option_of_sexp r_params_of_sexp x, session with
                | None, s -> s
                | Some r, Some (x::xs) ->
                  let sessions = { x with State.renegotiation = r } :: xs in
                  Some sessions
                | Some _, _ -> assert false
              in
              (sessions, ver, machina, config, hs_frag)
            | List [ Atom "machina" ; x ] -> (session, ver, Some (conv_machina maybe_state x), config, hs_frag)
            | List [ Atom "config" ; cfgs ] -> (session, ver, machina, Some (config_of_sexp cfgs), hs_frag)
            | List [ Atom "hs_fragment" ; x ] -> (session, ver, machina, config, Some (Cstruct_s.t_of_sexp x))
            | _ -> assert false)
          (Some sessions, None, None, None, None) eles
      with
      | Some session, Some protocol_version, Some machina, Some config, Some hs_fragment ->
        State.({ session ; protocol_version ; machina ; config ; hs_fragment })
      | _ -> assert false
    end
    | _ -> assert false


let conv_cst mac old cst =
  match old, cst with
  | State.Stream x, Stream ->
    guard (Nocrypto.Uncommon.Cs.equal x.State.hmac_secret mac) InvalidHmacKey ;
    State.Stream x
  | State.CBC c, Random ->
    guard (Nocrypto.Uncommon.Cs.equal c.State.hmac_secret mac) InvalidHmacKey ;
    guard (c.State.iv_mode = State.Random_iv) InvalidCipherState ;
    old
  | State.CBC c, Iv iv ->
    guard (Nocrypto.Uncommon.Cs.equal c.State.hmac_secret mac) InvalidHmacKey ;
    guard (not (c.State.iv_mode = State.Random_iv)) InvalidIv ;
    (State.CBC { c with State.iv_mode = State.Iv iv })
  | _ -> assert false

let conv_cc last proj sexp =
  match sexp_of_old_cc_option sexp with
  | None -> None
  | Some (sequence, cipher_state, mac) ->
    match last with
    | Some x ->
      let st = conv_cst mac x.State.cipher_st cipher_state in
      Some { State.sequence = sequence ; State.cipher_st = st }
    | None -> assert false

let conv_state maybe_st = function
  | List xs ->
    begin
      match
        List.fold_left (fun (hs, dec, enc, frag) -> function
            | List [ Atom "handshake" ; xs ] ->
              let hs = conv_handshake maybe_st xs in
              (Some hs, dec, enc, frag)
            | List [ Atom "decryptor" ; xs ] ->
              let last = match maybe_st with
                | None -> None
                | Some x -> x.State.decryptor
              in
              let dec = conv_cc last snd xs in
              (hs, Some dec, enc, frag)
            | List [ Atom "encryptor" ; xs ] ->
              let last = match maybe_st with
                | None -> None
                | Some x -> x.State.encryptor
              in
              let enc = conv_cc last fst xs in
              (hs, dec, Some enc, frag)
            | List [ Atom "fragment" ; xs ] -> (hs, dec, enc, Some (Cstruct_s.t_of_sexp xs))
            | _ -> assert false )
          (None, None, None, None) xs
      with
      | Some handshake, Some decryptor, Some encryptor, Some fragment ->
        State.({ handshake ; decryptor ; encryptor ; fragment })
      | _ -> assert false
    end
  | _ -> assert false

let fixup_in_record (hdr : Core.tls_hdr) data =
  Writer.assemble_any_hdr hdr.Core.version (hdr.Core.content_type, data)

let process_sexp acc x =
  let states = Utils.filter_map
      ~f:(function `StateIn x -> Some x | `StateOut x -> Some x | `State x -> Some x | _ -> None)
      acc
  in
  let top = match states with
    | [] -> None
    | x::_ -> Some x
  in
  match x with
  | List [ Atom "state-in" ; xs ] ->
    let state = conv_state top xs in
    (`StateIn state) :: acc
  | List [ Atom "state-out" ; xs ] ->
    let state = conv_state top xs in
    (`StateOut state) :: acc
  | List [ Atom "record-in" ; List [ List [ List [ Atom "content_type" ; ct ] ; List [ Atom "version" ; ver ] ] ; data ] ] ->
    let version = tls_ver_to_any_version (tls_ver_of_sexp ver)
    and content_type = Packet.content_type_of_sexp ct
    and data = Cstruct_s.t_of_sexp data
    in
    (`RecordIn (Core.({ content_type ; version }), data)) :: acc
  | List [ Atom "record-out" ; record ] ->
    let ro = rec_out_of_sexp record in
    (`RecordOut ro) :: acc
  | List [ Atom "application-data-in" ; data ] ->
    (`ApplicationDataIn (Cstruct_s.t_of_sexp data)) :: acc
  | List [ Atom "change-cipher-spec-out" ; _ ] ->
    let st = match top with
      | None -> assert false
      | Some x -> ( match x.State.handshake.State.machina with
          | State.Server (State.AwaitClientChangeCipherSpec (_, enc, dec, _)) ->
            { x with State.decryptor = Some dec ; State.encryptor = Some enc }
          | _ -> assert false )
    in
    `State st :: acc
  | List [ Atom "handshake-out" ; List [ Atom "Finished" ; _ ] ] ->
    let st = match top with
      | None -> assert false
      | Some st ->
        let hs = st.State.handshake in
        match hs.State.machina with
        | State.Server (State.AwaitClientFinished (session, _)) ->
          let session = session :: hs.State.session in
          let handshake = { hs with State.session = session } in
          { st with State.handshake = handshake }
        | _ -> assert false
    in
    `State st :: acc
  | List [ Atom "alert-out" ; alert ] ->
    `AlertOut (Core.tls_alert_of_sexp alert) :: acc
  | List [ Atom "alert-in" ; alert ] ->
    `AlertIn (Core.tls_alert_of_sexp alert) :: acc
  | List [ Atom "handshake-out" ; Atom "HelloRequest" ] ->
    `HelloRequest :: acc
  | List [ Atom x ; xs ] -> (* Printf.printf "ignoring %s\n" x ; *) acc
  | xs -> Printf.printf "unexpected %s\n" (to_string_hum xs) ; acc

let process_trace acc elements =
  List.fold_left process_sexp acc elements

let timestamp file =
  try Some (Scanf.sscanf file "%.05f" (fun x -> x))
  with _ -> None

let timestamp_to_string ts =
  let tm = Unix.gmtime ts in
  Printf.sprintf "%04d-%02d-%02d %02d:%02d:%02d"
    (1900 + tm.Unix.tm_year) (succ tm.Unix.tm_mon) tm.Unix.tm_mday
    tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec

let load_single_file acc file =
  match try Some (load_sexp file) with _ -> Printf.printf "error loading sexps\n" ; None with
    | None -> []
    | Some (List xs) -> process_trace acc xs
    | _ -> assert false

let eval_and_rev = function
  | `AlertOut alert::_ as xs -> (Some (Core.sexp_of_tls_alert alert), List.rev xs)
  | xs -> (None, List.rev xs)

let safe_ts t =
  match timestamp t with
  | Some x -> timestamp_to_string x
  | None -> ""

let load filename =
  match (Unix.stat filename).Unix.st_kind with
  | Unix.S_DIR ->
    let dir = Unix.opendir filename in
    let file = ref (try Some (Unix.readdir dir) with End_of_file -> None) in
    let acc = ref [] in
    while not (!file = None) do
      let filename = match !file with
        | Some x -> x
        | None -> assert false
      in
      (match timestamp filename with
       | Some x -> acc := (x, filename) :: !acc
       | None -> () ) ;
      file := try Some (Unix.readdir dir) with End_of_file -> None
    done ;
    (match List.map snd (List.sort (fun (a, _) (a', _) -> compare a a') !acc) with
     | [] -> fail EmptyDir
     | x :: xs ->
       (safe_ts x,
        eval_and_rev
          (List.fold_left (fun acc f ->
               load_single_file acc (Filename.concat filename f))
              [] (x :: xs))) )
  | Unix.S_REG ->
    (safe_ts (Filename.basename filename),
     eval_and_rev (load_single_file [] filename))
  | _ -> assert false

let load_dir (dir : string) (suc : (string * (string * (Sexplib.Sexp.t option * trace list)) -> unit)) (fai : string * read_error -> unit) =
  let dirent = Unix.opendir dir in
  let _ = Unix.readdir dirent in
  let _ = Unix.readdir dirent in (* getting rid of . and .. *)
  let filen = ref (try Some (Unix.readdir dirent) with End_of_file -> None) in
  let ign = ref 0 in
  while not (!filen = None) do
    let filename = match !filen with
      | None -> assert false
      | Some x -> x
    in
    (match
      (try Some (load (Filename.concat dir filename))
       with
       | Trace_error e -> fai (filename, e) ; None
       | e -> ign := succ !ign ; None)
    with
    | Some trace -> suc (filename, trace)
    | None -> ()) ;
    (filen := try Some (Unix.readdir dirent) with End_of_file -> None) ;
  done ;
  !ign
