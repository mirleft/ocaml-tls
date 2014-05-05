open Packet
open Core
open Cstruct

let (<+>) = Utils.Cs.(<+>)

let assemble_protocol_version_int buf version =
  let major, minor = pair_of_tls_version version in
  set_uint8 buf 0 major;
  set_uint8 buf 1 minor;
  buf

let assemble_protocol_version version =
  let buf = create 2 in
  assemble_protocol_version_int buf version

let assemble_hdr version (content_type, payload) =
  let buf = create 5 in
  set_uint8 buf 0 (content_type_to_int content_type);
  assemble_protocol_version_int (shift buf 1) version;
  BE.set_uint16 buf 3 (len payload);
  buf <+> payload

let assemble_certificate buf c =
  let length = len c in
  set_uint24_len buf length;
  blit c 0 buf 3 length;
  length + 3

let assemble_certificates cs =
  let length = List.fold_left (fun a b -> a + 3 + len b) 0 cs in
  let buf = create (length + 3) in
  let rec go buf = function
    | [] -> ()
    | c :: cs ->
       let l = assemble_certificate buf c in
       go (shift buf l) cs
  in
  go (shift buf 3) cs;
  set_uint24_len buf length;
  buf

let assemble_compression_method buf m =
  set_uint8 buf 0 (compression_method_to_int m);
  shift buf 1

let rec assemble_compression_methods buf = function
  | [] -> ()
  | m :: ms -> let buf = assemble_compression_method buf m in
               assemble_compression_methods buf ms

let assemble_ciphersuite buf c =
  BE.set_uint16 buf 0 (Ciphersuite.ciphersuite_to_int c);
  shift buf 2

let rec assemble_ciphersuites buf = function
  | [] -> ()
  | m :: ms ->
     let buf = assemble_ciphersuite buf m in
     assemble_ciphersuites buf ms

let assemble_named_curve buf nc =
  BE.set_uint16 buf 0 (named_curve_type_to_int nc);
  shift buf 2

let assemble_hostname host =
  (* 8 bit hostname type; 16 bit length; value *)
  let vallength = String.length host in
  let buf = create 3 in
  set_uint8 buf 0 0; (* type, only 0 registered *)
  BE.set_uint16 buf 1 vallength;
  buf <+> (of_string host)

let assemble_hostnames hosts =
  (* it should 16 bit length of list followed by the items *)
  let names = Utils.Cs.appends (List.map assemble_hostname hosts) in
  let buf = create 2 in
  BE.set_uint16 buf 0 (len names);
  buf <+> names

let assemble_signature_algorithms s =
  let rec assemble_sig buf = function
    | []        -> ()
    | (h,s)::xs ->
       set_uint8 buf 0 (hash_algorithm_to_int h);
       set_uint8 buf 1 (signature_algorithm_type_to_int s);
       assemble_sig (shift buf 2) xs
  in
  let len = 2 * (List.length s) in
  let buf = create (2 + len) in
  BE.set_uint16 buf 0 len;
  assemble_sig (shift buf 2) s;
  buf

let assemble_extension e =
  let pay, typ = match e with
    | SecureRenegotiation x ->
       let buf = create 1 in
       set_uint8 buf 0 (len x);
       (buf <+> x, RENEGOTIATION_INFO)
    | Hostname (Some name) ->
       (assemble_hostnames [name], SERVER_NAME)
    | Hostname None ->
       (create 0, SERVER_NAME)
    | Padding x ->
       let buf = create x in
       for i = 0 to pred x do
         set_uint8 buf i 0
       done;
       (buf, PADDING)
    | SignatureAlgorithms s ->
       (assemble_signature_algorithms s, SIGNATURE_ALGORITHMS)
  in
  let buf = create 4 in
  BE.set_uint16 buf 0 (extension_type_to_int typ);
  BE.set_uint16 buf 2 (Cstruct.len pay);
  buf <+> pay

let assemble_extensions = function
  | [] -> create 0
  | es -> let exts = Utils.Cs.appends (List.map assemble_extension es) in
          let l = len exts in
          let le = create 2 in
          BE.set_uint16 le 0 l;
          le <+> exts

let assemble_client_hello (cl : client_hello) : Cstruct.t =
  let slen = match cl.sessionid with
    | None -> 1
    | Some s -> 1 + len s
  in
  let cslen = 2 * List.length cl.ciphersuites in
  let bbuf = create (2 + 32 + slen + 2 + cslen + 1 + 1) in
  assemble_protocol_version_int bbuf cl.version;
  blit cl.random 0 bbuf 2 32;
  let buf = shift bbuf 34 in
  (match cl.sessionid with
   | None ->
      set_uint8 buf 0 0;
   | Some s ->
      let slen = len s in
      set_uint8 buf 0 slen;
      blit s 0 buf 1 slen);
  let buf = shift buf slen in
  BE.set_uint16 buf 0 (2 * List.length cl.ciphersuites);
  let buf = shift buf 2 in
  assemble_ciphersuites buf cl.ciphersuites;
  let buf = shift buf cslen in
  (* compression methods, completely useless *)
  set_uint8 buf 0 1;
  let buf = shift buf 1 in
  assemble_compression_methods buf [NULL];
  (* some widely deployed firewalls drop ClientHello messages which are
     > 256 and < 511 byte, insert PADDING extension for these *)
  (* from draft-agl-tls-padding-03:
   As an example, consider a client that wishes to avoid sending a
   ClientHello with a record size between 256 and 511 bytes (inclusive).
   This case is considered because at least one TLS implementation is
   known to hang the connection when such a ClientHello record is
   received.

   After building a ClientHello as normal, the client can add four to
   the length (to account for the "msg_type" and "length" fields of the
   handshake protocol) and test whether the resulting length falls into
   that range.  If it does, a padding extension can be added in order to
   push the length to (at least) 512 bytes. *)
  let extensions = assemble_extensions cl.extensions in
  let extrapadding =
    let buflen = len bbuf + len extensions + 4 in
    if buflen >= 256 && buflen <= 511 then
      match len extensions with
        | 0 -> (* need to construct a 2 byte extension length as well *)
           let p = assemble_extension (Padding (506 - buflen)) in
           let le = create 2 in
           BE.set_uint16 le 0 (len p + 4);
           le <+> p
        | _ ->
           let l = 508 - buflen in
           let p = assemble_extension (Padding l) in
           BE.set_uint16 extensions 0 (len extensions + l + 4);
           p
    else
      create 0
  in
  bbuf <+> extensions <+> extrapadding

let assemble_server_hello (sh : server_hello) : Cstruct.t =
  let slen = match sh.sessionid with
    | None -> 1
    | Some s -> 1 + len s
  in
  let bbuf = create (2 + 32 + slen + 2 + 1) in
  assemble_protocol_version_int bbuf sh.version;
  blit sh.random 0 bbuf 2 32;
  let buf = shift bbuf 34 in
  (match sh.sessionid with
   | None -> set_uint8 buf 0 0;
   | Some s -> let slen = len s in
               set_uint8 buf 0 slen;
               blit s 0 buf 1 slen);
  let buf = shift buf slen in
  let buf = assemble_ciphersuite buf sh.ciphersuites in
  (* useless compression method *)
  let _ = assemble_compression_method buf NULL in
  let extensions = assemble_extensions sh.extensions in
  bbuf <+> extensions

let assemble_dh_parameters p =
  let plen, glen, yslen = (len p.dh_p, len p.dh_g, len p.dh_Ys) in
  let buf = create (2 + 2 + 2 + plen + glen + yslen) in
  BE.set_uint16  buf  0 plen;
  blit p.dh_p  0 buf  2 plen;
  BE.set_uint16  buf (2 + plen) glen;
  blit p.dh_g  0 buf (4 + plen) glen;
  BE.set_uint16  buf (4 + plen + glen) yslen;
  blit p.dh_Ys 0 buf (6 + plen + glen) yslen;
  buf

let assemble_digitally_signed signature =
  let lenbuf = create 2 in
  BE.set_uint16 lenbuf 0 (len signature);
  lenbuf <+> signature

let assemble_digitally_signed_1_2 hashalgo sigalgo signature =
  let algobuf = create 2 in
  set_uint8 algobuf 0 (hash_algorithm_to_int hashalgo);
  set_uint8 algobuf 1 (signature_algorithm_type_to_int sigalgo);
  algobuf <+> (assemble_digitally_signed signature)

let assemble_client_key_exchange kex =
  let len = len kex in
  let buf = create (len + 2) in
  BE.set_uint16 buf 0 len;
  blit kex 0 buf 2 len;
  buf

let assemble_handshake hs =
  let (payload, payload_type) =
    match hs with
    | ClientHello ch -> (assemble_client_hello ch, CLIENT_HELLO)
    | ServerHello sh -> (assemble_server_hello sh, SERVER_HELLO)
    | Certificate cs -> (assemble_certificates cs, CERTIFICATE)
    | ServerKeyExchange kex -> (kex, SERVER_KEY_EXCHANGE)
    | ClientKeyExchange kex -> (assemble_client_key_exchange kex, CLIENT_KEY_EXCHANGE)
    | ServerHelloDone -> (create 0, SERVER_HELLO_DONE)
    | HelloRequest -> (create 0, HELLO_REQUEST)
    | Finished fs -> (fs, FINISHED)
  in
  let pay_len = len payload in
  let buf = create 4 in
  set_uint8 buf 0 (handshake_type_to_int payload_type);
  set_uint24_len (shift buf 1) pay_len;
  buf <+> payload

let assemble_alert ?level typ =
  let buf = create 2 in
  set_uint8 buf 1 (alert_type_to_int typ);
  (match level with
   | None -> set_uint8 buf 0 (alert_level_to_int Packet.FATAL)
   | Some x -> set_uint8 buf 0 (alert_level_to_int x));
  buf

let assemble_change_cipher_spec =
  let ccs = create 1 in
  set_uint8 ccs 0 1;
  ccs
