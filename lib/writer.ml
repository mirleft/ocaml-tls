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

let assemble_certificates buf cs =
  let rec go buf len = function
    | [] -> len
    | c :: cs ->
       let l = assemble_certificate buf c in
       go (Cstruct.shift buf l) (l + len) cs
  in
  let lens = go (Cstruct.shift buf 3) 0 cs in
  set_uint24_len buf lens;
  lens + 3

let assemble_compression_method buf m =
  Cstruct.set_uint8 buf 0 (compression_method_to_int m);
  Cstruct.shift buf 1

let rec assemble_compression_methods buf acc = function
  | [] -> acc
  | m :: ms -> let buf = assemble_compression_method buf m in
               assemble_compression_methods buf (acc + 1) ms

let assemble_ciphersuite buf c =
  Cstruct.BE.set_uint16 buf 0 (Ciphersuite.ciphersuite_to_int c);
  Cstruct.shift buf 2

let rec assemble_ciphersuites buf acc = function
  | [] -> acc
  | m :: ms ->
     let buf = assemble_ciphersuite buf m in
     assemble_ciphersuites buf (acc + 2) ms

let assemble_named_curve buf nc =
  Cstruct.BE.set_uint16 buf 0 (named_curve_type_to_int nc);
  Cstruct.shift buf 2

let assemble_client_hello buf cl =
  let (major, minor) = cl.version in
  set_c_hello_major_version buf major;
  set_c_hello_minor_version buf minor;
  Cstruct.blit cl.random 0 buf 6 32;
  let buf = Cstruct.shift buf 34 in
  let slen = match cl.sessionid with
    | None ->
       Cstruct.set_uint8 buf 0 0;
       1
    | Some s ->
       let slen = Cstruct.len s in
       Cstruct.set_uint8 buf 0 slen;
       Cstruct.blit s 0 buf 1 slen;
       slen + 1
  in
  let buf = Cstruct.shift buf slen in
  Cstruct.BE.set_uint16 buf 0 (2 * List.length cl.ciphersuites);
  let buf = Cstruct.shift buf 2 in
  let cslen = assemble_ciphersuites buf 0 cl.ciphersuites in
  (* compression methods, completely useless *)
  Cstruct.set_uint8 buf 0 1;
  let buf = Cstruct.shift buf 1 in
  let clen = assemble_compression_methods buf 0 [NULL] in
  (* extensions *)
  34 + slen + cslen + 2 + 1 + clen + 2

let assemble_server_hello buf (sh : server_hello) =
  let (major, minor) = sh.version in
  set_c_hello_major_version buf major;
  set_c_hello_minor_version buf minor;
  Cstruct.blit sh.random 0 buf 6 32;
  let buf = Cstruct.shift buf 34 in
  let slen = match sh.sessionid with
    | None ->
       Cstruct.set_uint8 buf 0 0;
       1
    | Some s ->
       let slen = Cstruct.len s in
       Cstruct.set_uint8 buf 0 slen;
       Cstruct.blit s 0 buf 1 slen;
       slen + 1
  in
  let buf = Cstruct.shift buf slen in
  let buf = assemble_ciphersuite buf sh.ciphersuites in
  (* useless compression method *)
  let _ = assemble_compression_method buf NULL in
  (* extensions *)
(*  Cstruct.BE.set_uint16 buf 0 (List.length sh.extensions); *)
  34 + slen + 2 + 1

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
