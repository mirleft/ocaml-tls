open Packet
open Core

let (<>) = Utils.cs_append

let assemble_hdr (content_type, payload) =
  let payloadlength = Cstruct.len payload in
  let buf = Cstruct.create (5 + payloadlength) in
  Cstruct.blit payload 0 buf 5 payloadlength;
  set_tls_h_content_type buf (content_type_to_int content_type);
  let (major, minor) = (3, 1) in
  set_tls_h_major_version buf major;
  set_tls_h_minor_version buf minor;
  set_tls_h_length buf payloadlength;
  buf

let assemble_certificate buf c =
  let len = Cstruct.len c in
  set_uint24_len buf len;
  Cstruct.blit c 0 buf 3 len;
  len + 3

let assemble_certificates cs =
  let len = List.fold_left (fun a b -> a + 3 + Cstruct.len b) 0 cs in
  let buf = Cstruct.create (len + 3) in
  let rec go buf = function
    | [] -> ()
    | c :: cs ->
       let l = assemble_certificate buf c in
       go (Cstruct.shift buf l) cs
  in
  go (Cstruct.shift buf 3) cs;
  set_uint24_len buf len;
  buf

let assemble_compression_method buf m =
  Cstruct.set_uint8 buf 0 (compression_method_to_int m);
  Cstruct.shift buf 1

let rec assemble_compression_methods buf = function
  | [] -> ()
  | m :: ms -> let buf = assemble_compression_method buf m in
               assemble_compression_methods buf ms

let assemble_ciphersuite buf c =
  Cstruct.BE.set_uint16 buf 0 (Ciphersuite.ciphersuite_to_int c);
  Cstruct.shift buf 2

let rec assemble_ciphersuites buf = function
  | [] -> ()
  | m :: ms ->
     let buf = assemble_ciphersuite buf m in
     assemble_ciphersuites buf ms

let assemble_named_curve buf nc =
  Cstruct.BE.set_uint16 buf 0 (named_curve_type_to_int nc);
  Cstruct.shift buf 2

let assemble_extension e =
  let pay, typ = match e with
    | SecureRenegotiation x ->
       let buf = Cstruct.create 1 in
       Cstruct.set_uint8 buf 0 (Cstruct.len x);
       (buf <> x, RENEGOTIATION_INFO)
    | _ -> assert false
  in
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint16 buf 0 (extension_type_to_int typ);
  Cstruct.BE.set_uint16 buf 2 (Cstruct.len pay);
  buf <> pay

let assemble_extensions = function
  | [] -> Cstruct.create 0
  | es -> let exts = Utils.cs_appends (List.map assemble_extension es) in
          let lenbuf = Cstruct.create 2 in
          Cstruct.BE.set_uint16 lenbuf 0 (Cstruct.len exts);
          lenbuf <> exts

let assemble_client_hello (cl : client_hello) : Cstruct.t =
  let slen = match cl.sessionid with
    | None -> 1
    | Some s -> 1 + Cstruct.len s
  in
  let cslen = 2 * List.length cl.ciphersuites in
  let bbuf = Cstruct.create (2 + 32 + slen + 2 + cslen + 1 + 1) in
  let (major, minor) = cl.version in
  set_c_hello_major_version bbuf major;
  set_c_hello_minor_version bbuf minor;
  Cstruct.blit cl.random 0 bbuf 2 32;
  let buf = Cstruct.shift bbuf 34 in
  (match cl.sessionid with
   | None ->
      Cstruct.set_uint8 buf 0 0;
   | Some s ->
      let slen = Cstruct.len s in
      Cstruct.set_uint8 buf 0 slen;
      Cstruct.blit s 0 buf 1 slen);
  let buf = Cstruct.shift buf slen in
  Cstruct.BE.set_uint16 buf 0 (2 * List.length cl.ciphersuites);
  let buf = Cstruct.shift buf 2 in
  assemble_ciphersuites buf cl.ciphersuites;
  let buf = Cstruct.shift buf cslen in
  (* compression methods, completely useless *)
  Cstruct.set_uint8 buf 0 1;
  let buf = Cstruct.shift buf 1 in
  assemble_compression_methods buf [NULL];
  bbuf <> (assemble_extensions cl.extensions)

let assemble_server_hello (sh : server_hello) : Cstruct.t =
  let slen = match sh.sessionid with
    | None -> 1
    | Some s -> 1 + Cstruct.len s
  in
  let bbuf = Cstruct.create (2 + 32 + slen + 2 + 1) in
  let (major, minor) = sh.version in
  set_c_hello_major_version bbuf major;
  set_c_hello_minor_version bbuf minor;
  Cstruct.blit sh.random 0 bbuf 2 32;
  let buf = Cstruct.shift bbuf 34 in
  (match sh.sessionid with
   | None -> Cstruct.set_uint8 buf 0 0;
   | Some s -> let slen = Cstruct.len s in
               Cstruct.set_uint8 buf 0 slen;
               Cstruct.blit s 0 buf 1 slen);
  let buf = Cstruct.shift buf slen in
  let buf = assemble_ciphersuite buf sh.ciphersuites in
  (* useless compression method *)
  let _ = assemble_compression_method buf NULL in
  bbuf <> (assemble_extensions sh.extensions)

let assemble_ec_prime_parameters buf pp = 0

let assemble_ec_char_parameters buf cp = 0

let assemble_ec_parameters buf = function
  | ExplicitPrimeParameters pp ->
     Cstruct.set_uint8 buf 0 (ec_curve_type_to_int EXPLICIT_PRIME);
     1 + (assemble_ec_prime_parameters (Cstruct.shift buf 1) pp)
  | ExplicitCharParameters cp ->
     Cstruct.set_uint8 buf 0 (ec_curve_type_to_int EXPLICIT_CHAR2);
     1 + (assemble_ec_char_parameters (Cstruct.shift buf 1) cp)
  | NamedCurveParameters (np, pub) ->
     Cstruct.set_uint8 buf 0 (ec_curve_type_to_int NAMED_CURVE);
     let buf = assemble_named_curve buf np in
     let len = Cstruct.len pub in
     Cstruct.set_uint8 buf 0 len;
     Cstruct.blit pub 0 buf 1 len;
     (4 + len)

let assemble_dh_parameters p =
  let plen, glen, yslen = Cstruct.(len p.dh_p, len p.dh_g, len p.dh_Ys ) in
  let buf = Cstruct.create (2 + 2 + 2 + plen + glen + yslen) in
  Cstruct.BE.set_uint16  buf  0 plen;
  Cstruct.blit p.dh_p  0 buf  2 plen;
  Cstruct.BE.set_uint16  buf (2 + plen) glen;
  Cstruct.blit p.dh_g  0 buf (4 + plen) glen;
  Cstruct.BE.set_uint16  buf (4 + plen + glen) yslen;
  Cstruct.blit p.dh_Ys 0 buf (6 + plen + glen) yslen;
  buf

let assemble_dh_parameters_and_signature pbuf signature =
  let plen = Cstruct.len pbuf in
  let buf = Cstruct.create (2 + plen) in
  Cstruct.BE.set_uint16 buf plen (Cstruct.len signature);
  Cstruct.blit pbuf 0 buf 0 plen;
  buf <> signature

let assemble_client_key_exchange kex =
  let len = Cstruct.len kex in
  let buf = Cstruct.create (len + 2) in
  Cstruct.BE.set_uint16 buf 0 len;
  Cstruct.blit kex 0 buf 2 len;
  buf

let assemble_handshake hs =
  let (payload, payload_type) =
    match hs with
    | ClientHello ch -> (assemble_client_hello ch, CLIENT_HELLO)
    | ServerHello sh -> (assemble_server_hello sh, SERVER_HELLO)
    | Certificate cs -> (assemble_certificates cs, CERTIFICATE)
    | ServerKeyExchange kex -> (kex, SERVER_KEY_EXCHANGE)
    | ClientKeyExchange kex -> (assemble_client_key_exchange kex, CLIENT_KEY_EXCHANGE)
    | ServerHelloDone -> (Cstruct.create 0, SERVER_HELLO_DONE)
    | Finished fs -> (fs, FINISHED)
    | _ -> assert false
  in
  let pay_len = Cstruct.len payload in
  let buf = Cstruct.create (pay_len + 4) in
  Cstruct.blit payload 0 buf 4 pay_len;
  Cstruct.set_uint8 buf 0 (handshake_type_to_int payload_type);
  set_uint24_len (Cstruct.shift buf 1) pay_len;
  Printf.printf "assembled %s into a buf of size %d\n" (handshake_type_to_string payload_type) pay_len;
  Cstruct.hexdump buf;
  buf
