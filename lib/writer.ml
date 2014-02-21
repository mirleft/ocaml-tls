open Packet
open Core

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

let assemble_client_hello (cl : client_hello) : Cstruct.t =
  let slen = match cl.sessionid with
    | None -> 1
    | Some s -> 1 + Cstruct.len s
  in
  let cslen = 2 * List.length cl.ciphersuites in
  let buf = Cstruct.create (2 + 32 + slen + 2 + cslen + 1 + 1) (* TODO : extensions *) in
  let (major, minor) = cl.version in
  set_c_hello_major_version buf major;
  set_c_hello_minor_version buf minor;
  Cstruct.blit cl.random 0 buf 2 32;
  let buf = Cstruct.shift buf 34 in
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
  (* extensions *)
  buf

let assemble_server_hello (sh : server_hello) : Cstruct.t =
  let slen = match sh.sessionid with
    | None -> 1
    | Some s -> 1 + Cstruct.len s
  in
  let buf = Cstruct.create (2 + 32 + slen + 2 + 1) (* extensions *) in
  let (major, minor) = sh.version in
  set_c_hello_major_version buf major;
  set_c_hello_minor_version buf minor;
  Cstruct.blit sh.random 0 buf 2 32;
  let buf = Cstruct.shift buf 34 in
  (match sh.sessionid with
   | None -> Cstruct.set_uint8 buf 0 0;
   | Some s -> let slen = Cstruct.len s in
               Cstruct.set_uint8 buf 0 slen;
               Cstruct.blit s 0 buf 1 slen);
  let buf = Cstruct.shift buf slen in
  let buf = assemble_ciphersuite buf sh.ciphersuites in
  (* useless compression method *)
  let _ = assemble_compression_method buf NULL in
  (* extensions *)
  (* Cstruct.BE.set_uint16 buf 0 (List.length sh.extensions); *)
  buf

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

let assemble_handshake hs =
  let (payload, payload_type) =
    match hs with
    | ClientHello ch -> (assemble_client_hello ch, CLIENT_HELLO)
    | ServerHello sh -> (assemble_server_hello sh, SERVER_HELLO)
    | Certificate cs -> (assemble_certificates cs, CERTIFICATE)
(*    | ServerKeyExchange kex -> (assemble_server_key_exchange kex, SERVER_KEY_EXCHANGE) *)
    | ServerHelloDone -> (Cstruct.create 0, SERVER_HELLO_DONE)
    | Finished fs -> (fs, FINISHED)
    | _ -> assert false
  in
  let pay_len = Cstruct.len payload in
  let buf = Cstruct.create (pay_len + 4) in
  Cstruct.blit payload 0 buf 4 pay_len;
  Cstruct.set_uint8 buf 0 (handshake_type_to_int payload_type);
  set_uint24_len (Cstruct.shift buf 1) pay_len;
  buf
