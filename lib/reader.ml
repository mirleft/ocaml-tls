open Packet
open Core

type error =
  | Overflow
  | Unknown of string

module Or_error =
  Control.Or_error_make (struct type err = error end)
open Or_error

let check_length len buf =
  match (Cstruct.len buf) >= len with
  | false -> fail Overflow
  | treu  -> return ()

let parse_version buf =
  check_length 2 buf >>= fun () ->
  let major = Cstruct.get_uint8 buf 0 in
  let minor = Cstruct.get_uint8 buf 1 in
  return (major, minor)

let parse_hdr buf =
  check_length 5 buf >>= fun () ->
  let typ = Cstruct.get_uint8 buf 0 in
  match int_to_content_type typ with
  | None              ->
     fail (Unknown ("content type " ^ string_of_int typ))
  | Some content_type ->
     parse_version (Cstruct.shift buf 1) >>= fun (version) ->
     let len = Cstruct.BE.get_uint16 buf 3 in
     let payload = Cstruct.shift buf 5 in
     return ({ content_type; version }, payload, len)

let parse_alert buf =
  check_length 2 buf >>= fun () ->
  let level = Cstruct.get_uint8 buf 0 in
  let typ = Cstruct.get_uint8 buf 1 in
  match int_to_alert_level level, int_to_alert_type typ with
    | (Some lvl, Some msg) -> return (lvl, msg)
    | (Some _  , None)     -> fail (Unknown ("alert type " ^ string_of_int typ))
    | _                    -> fail (Unknown ("alert level " ^ string_of_int level))

let rec parse_certificate_types buf acc = function
  | 0 -> return acc
  | n ->
     check_length 1 buf >>= fun () ->
     let typ = Cstruct.get_uint8 buf 0 in
     match int_to_client_certificate_type typ with
     | Some x -> parse_certificate_types (Cstruct.shift buf 1) (x :: acc) (n - 1)
     | None -> fail (Unknown ("certificate type: " ^ string_of_int typ))

let rec parse_cas buf acc =
  match (Cstruct.len buf) with
  | 0 -> return acc
  | n ->
     check_length 2 buf >>= fun () ->
     let len = Cstruct.BE.get_uint16 buf 0 in
     check_length (2 + len) buf >>= fun () ->
     let name = Cstruct.copy buf 2 len in
     parse_cas (Cstruct.shift buf (2 + len)) (name :: acc)

let parse_certificate_request buf =
  check_length 1 buf >>= fun () ->
  let typeslen = Cstruct.get_uint8 buf 0 in
  let tbuf = Cstruct.shift buf 1 in
  check_length typeslen tbuf >>= fun () ->
  parse_certificate_types tbuf [] typeslen >>= fun (certificate_types) ->
  let cabuf = Cstruct.shift tbuf typeslen in
  check_length 2 cabuf >>= fun () ->
  let calength = Cstruct.BE.get_uint16 buf 0 in
  let cabuf' = Cstruct.shift cabuf 2 in
  check_length calength cabuf' >>= fun () ->
  parse_cas cabuf' [] >>= fun (certificate_authorities) ->
  return (CertificateRequest { certificate_types ; certificate_authorities })

let parse_compression_method buf =
  check_length 1 buf >>= fun () ->
  let cm = Cstruct.get_uint8 buf 0 in
  match int_to_compression_method cm with
  | Some x -> return (x, 1)
  | None   -> fail (Unknown ("compression method: " ^ string_of_int cm))

let parse_compression_methods buf =
  let rec go buf acc = function
    | 0 -> return acc
    | n ->
       parse_compression_method buf >>= fun (cm, b) ->
       go (Cstruct.shift buf b) (cm :: acc) (n - 1)
  in
  check_length 1 buf >>= fun () ->
  let len = Cstruct.get_uint8 buf 0 in
  check_length (1 + len) buf >>= fun () ->
  go (Cstruct.shift buf 1) [] len >>= fun (methods) ->
  return (methods, len + 1)

let parse_ciphersuite buf =
  check_length 2 buf >>= fun () ->
  let typ = Cstruct.BE.get_uint16 buf 0 in
  match Ciphersuite.int_to_ciphersuite typ with
  | Some x -> return (x, 2)
  | None -> fail (Unknown ("ciphersuite: " ^ string_of_int typ))

let parse_ciphersuites buf =
  let rec go buf acc = function
    | 0 -> return acc
    | n ->
       parse_ciphersuite buf >>= fun (suite, l) ->
       go (Cstruct.shift buf l) (suite :: acc) (n - 1)
  in
  check_length 2 buf >>= fun () ->
  let len = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + len) buf >>= fun () ->
  go (Cstruct.shift buf 2) [] (len / 2) >>= fun (suites) ->
  return (List.rev suites, len + 2)

let parse_hostnames buf =
  if Cstruct.len buf > 1 then
    check_length 2 buf >>= fun () ->
    let list_length = Cstruct.BE.get_uint16 buf 0 in
    check_length (2 + list_length) buf >>= fun () ->
    let rec go buf acc =
      match Cstruct.len buf with
      | 0 -> return acc
      | n ->
         check_length 1 buf >>= fun () ->
         let name_type = Cstruct.get_uint8 buf 0 in
         match name_type with
         | 0 ->
            check_length 3 buf >>= fun () ->
            let hostname_length = Cstruct.BE.get_uint16 buf 1 in
            check_length (3 + hostname_length) buf >>= fun () ->
            let buf' = Cstruct.shift buf (3 + hostname_length) in
            let host = Cstruct.copy buf 3 hostname_length in
            go buf' (host :: acc)
         | _ -> fail (Unknown ("name_type: " ^ string_of_int name_type))
    in
    go (Cstruct.sub buf 2 list_length) []
  else
    return []

let parse_fragment_length buf =
  check_length 1 buf >>= fun () ->
  let typ = Cstruct.get_uint8 buf 0 in
  match int_to_max_fragment_length typ with
  | Some x -> return x
  | None   -> fail (Unknown ("fragment_length: " ^ string_of_int typ))

let parse_named_curve buf =
  check_length 1 buf >>= fun () ->
  let typ = Cstruct.BE.get_uint16 buf 0 in
  match int_to_named_curve_type typ with
  | Some x -> return x
  | None -> fail (Unknown ("named curve: " ^ string_of_int typ))

let parse_elliptic_curves buf =
  let rec go buf acc = match Cstruct.len buf with
    | 0 -> return acc
    | n ->
       check_length 2 buf >>= fun () ->
       parse_named_curve buf >>= fun (c) ->
       go (Cstruct.shift buf 2) (c :: acc)
  in
  check_length 2 buf >>= fun () ->
  let len = Cstruct.BE.get_uint16 buf 0 in
  go (Cstruct.sub buf 2 len) []

let parse_ec_point_format buf =
  let rec go buf acc = match Cstruct.len buf with
    | 0 -> return acc
    | n ->
       check_length 1 buf >>= fun () ->
       let typ = Cstruct.get_uint8 buf 0 in
       match int_to_ec_point_format typ with
         | Some fmt -> go (Cstruct.shift buf 1) (fmt :: acc)
         | None     -> fail (Unknown ("ec point format: " ^ string_of_int typ))
  in
  check_length 1 buf >>= fun () ->
  let len = Cstruct.get_uint8 buf 0 in
  go (Cstruct.sub buf 1 len) []

let parse_extension buf =
  check_length 4 buf >>= fun () ->
  let etype = Cstruct.BE.get_uint16 buf 0 in
  let len = Cstruct.BE.get_uint16 buf 2 in
  let buf = Cstruct.sub buf 4 len in
  ( match int_to_extension_type etype with
    | Some SERVER_NAME ->
       parse_hostnames buf >>= fun (hosts) ->
       ( match hosts with
         | []     -> return (Hostname None)
         | [name] -> return (Hostname (Some name))
         | _      -> fail (Unknown "bad server_name extension") )
    | Some MAX_FRAGMENT_LENGTH ->
       parse_fragment_length buf >>= fun (len) ->
       return (MaxFragmentLength len)
    | Some ELLIPTIC_CURVES ->
       parse_elliptic_curves buf >>= fun (curves) ->
       return (EllipticCurves curves)
    | Some EC_POINT_FORMATS ->
       parse_ec_point_format buf >>= fun (formats) ->
       return (ECPointFormats formats)
    | Some RENEGOTIATION_INFO ->
       check_length 1 buf >>= fun () ->
       return (SecureRenegotiation (Cstruct.shift buf 1))
    | None -> fail (Unknown ("extension: " ^ string_of_int etype)) ) >>= fun (data) ->
  return (data, 4 + len)

let parse_extensions buf =
  let rec go buf acc =
    match Cstruct.len buf with
    | 0 -> return acc
    | n ->
       parse_extension buf >>= fun (extension, esize) ->
       go (Cstruct.shift buf esize) (extension :: acc)
  in
  check_length 2 buf >>= fun () ->
  let len = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + len) buf >>= fun () ->
  go (Cstruct.sub buf 2 len) [] >>= fun (exts) ->
  return (exts, 2 + len)

let parse_hello get_compression get_cipher buf =
  parse_version buf >>= fun (version) ->
  check_length 35 buf >>= fun () ->
  let random = Cstruct.sub buf 2 32 in
  let slen = Cstruct.get_uint8 buf 34 in
  check_length (35 + slen) buf >>= fun () ->
  let sessionid = if slen = 0 then None else Some (Cstruct.sub buf 35 slen) in
  get_cipher (Cstruct.shift buf (35 + slen)) >>= fun (ciphersuites, clen) ->
  get_compression (Cstruct.shift buf (35 + slen + clen)) >>= fun (_, dlen) ->
  ( if Cstruct.len buf > (35 + slen + clen + dlen) then
      parse_extensions (Cstruct.shift buf (35 + slen + clen + dlen))
    else
      return ([], 0) ) >>= fun (extensions, _) ->
  return { version ; random ; sessionid ; ciphersuites ; extensions }

let parse_client_hello buf =
  parse_hello parse_compression_methods parse_ciphersuites buf >>= fun (ch) ->
  return (ClientHello ch)

let parse_server_hello buf =
  parse_hello parse_compression_method parse_ciphersuite buf >>= fun (sh) ->
  return (ServerHello sh)

let parse_certificate buf =
  check_length 3 buf >>= fun () ->
  let len = get_uint24_len buf in
  check_length (3 + len) buf >>= fun () ->
  return ((Cstruct.sub buf 3 len), len + 3)

(* hahaha get some, geddit?? *)
(*
let get_some prs buf =
  let go buf = match (Cstruct.len buf) with
    | 0 -> []
    | n -> let x, buf' = prs buf in x :: go buf' in
  let len = get_uint24_len buf in
  go (Cstruct.sub buf 3 len)
*)

let parse_certificates buf =
  let rec go buf acc =
            match (Cstruct.len buf) with
            | 0 -> return (List.rev acc)
            | n -> parse_certificate buf >>= fun (cert, size) ->
                   go (Cstruct.shift buf size) (cert :: acc)
  in
  check_length 3 buf >>= fun () ->
  let len = get_uint24_len buf in
  check_length (3 + len) buf >>= fun () ->
  go (Cstruct.sub buf 3 len) [] >>= fun (cs) ->
  return (Certificate cs)

let parse_rsa_parameters buf =
  check_length 2 buf >>= fun () ->
  let mlength = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + mlength) buf >>= fun () ->
  let rsa_modulus = Cstruct.sub buf 2 mlength in
  let buf = Cstruct.shift buf (2 + mlength) in
  check_length 2 buf >>= fun () ->
  let elength = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + elength) buf >>= fun () ->
  let rsa_exponent = Cstruct.sub buf 2 elength in
  return ({ rsa_modulus ; rsa_exponent }, 4 + mlength + elength)

let parse_dh_parameters_and_signature raw =
  check_length 2 raw >>= fun () ->
  let plength = Cstruct.BE.get_uint16 raw 0 in
  check_length (2 + plength) raw >>= fun () ->
  let dh_p = Cstruct.sub raw 2 plength in
  let buf = Cstruct.shift raw (2 + plength) in
  check_length 2 buf >>= fun () ->
  let glength = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + glength) buf >>= fun () ->
  let dh_g = Cstruct.sub buf 2 glength in
  let buf = Cstruct.shift buf (2 + glength) in
  check_length 2 buf >>= fun () ->
  let yslength = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + yslength) buf >>= fun () ->
  let dh_Ys = Cstruct.sub buf 2 yslength in
  let buf = Cstruct.shift buf (2 + yslength) in
  check_length 2 buf >>= fun () ->
  let siglen = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + siglen) buf >>= fun () ->
  let sign = Cstruct.sub buf 2 siglen in
  return ({ dh_p ; dh_g; dh_Ys }, sign,
          Cstruct.sub raw 0 (plength + glength + yslength + 6) )

let parse_ec_curve buf =
  check_length 1 buf >>= fun () ->
  let al = Cstruct.get_uint8 buf 0 in
  check_length (1 + al) buf >>= fun () ->
  let a = Cstruct.sub buf 1 al in
  let buf = Cstruct.shift buf (1 + al) in
  check_length 1 buf >>= fun () ->
  let bl = Cstruct.get_uint8 buf 0 in
  check_length (1 + bl) buf >>= fun () ->
  let b = Cstruct.sub buf 1 bl in
  let buf = Cstruct.shift buf (1 + bl) in
  return ({ a ; b }, buf)

let parse_ec_prime_parameters buf =
  check_length 1 buf >>= fun () ->
  let plen = Cstruct.get_uint8 buf 0 in
  check_length (1 + plen) buf >>= fun () ->
  let prime = Cstruct.sub buf 1 plen in
  let buf = Cstruct.shift buf (1 + plen) in
  parse_ec_curve buf >>= fun (curve, buf) ->
  check_length 1 buf >>= fun () ->
  let blen = Cstruct.get_uint8 buf 0 in
  check_length (1 + blen) buf >>= fun () ->
  let base = Cstruct.sub buf 1 blen in
  let buf = Cstruct.shift buf (1 + blen) in
  check_length 1 buf >>= fun () ->
  let olen = Cstruct.get_uint8 buf 0 in
  check_length (1 + olen) buf >>= fun () ->
  let order = Cstruct.sub buf 1 olen in
  let buf = Cstruct.shift buf (1 + olen) in
  check_length 1 buf >>= fun () ->
  let cofactorlength = Cstruct.get_uint8 buf 0 in
  check_length (1 + cofactorlength) buf >>= fun () ->
  let cofactor = Cstruct.sub buf 1 cofactorlength in
  let buf = Cstruct.shift buf (1 + cofactorlength) in
  check_length 1 buf >>= fun () ->
  let publiclen = Cstruct.get_uint8 buf 0 in
  check_length (1 + publiclen) buf >>= fun () ->
  let public = Cstruct.sub buf 1 publiclen in
  let buf = Cstruct.shift buf (1 + publiclen) in
  return ({ prime ; curve ; base ; order ; cofactor ; public }, buf)

let parse_ec_char_parameters buf =
  check_length 3 buf >>= fun () ->
  let m = Cstruct.BE.get_uint16 buf 0 in
  let typ = Cstruct.get_uint8 buf 2 in
  ( match int_to_ec_basis_type typ with
    | Some x -> return x
    | None -> fail (Unknown ("basis type: " ^ string_of_int typ)) ) >>= fun (basis) ->
  let buf = Cstruct.shift buf 3 in
  ( match basis with
    | TRINOMIAL ->
       check_length 1 buf >>= fun () ->
       let len = Cstruct.get_uint8 buf 0 in
       check_length (1 + len) buf >>= fun () ->
       return ([Cstruct.sub buf 1 len], Cstruct.shift buf (len + 1))
    | PENTANOMIAL ->
       check_length 1 buf >>= fun () ->
       let k1len = Cstruct.get_uint8 buf 0 in
       check_length (1 + k1len) buf >>= fun () ->
       let k1 = Cstruct.sub buf 1 k1len in
       let buf = Cstruct.shift buf (k1len + 1) in
       check_length 1 buf >>= fun () ->
       let k2len = Cstruct.get_uint8 buf 0 in
       check_length (1 + k2len) buf >>= fun () ->
       let k2 = Cstruct.sub buf 1 k2len in
       let buf = Cstruct.shift buf (k2len + 1) in
       check_length 1 buf >>= fun () ->
       let k3len = Cstruct.get_uint8 buf 0 in
       check_length (1 + k3len) buf >>= fun () ->
       let k3 = Cstruct.sub buf 1 k3len in
       return ([k1; k2; k3], Cstruct.shift buf (k3len + 1)) ) >>= fun (ks, buf) ->
  parse_ec_curve buf >>= fun (curve, buf) ->
  check_length 1 buf >>= fun () ->
  let blen = Cstruct.get_uint8 buf 0 in
  check_length (1 + blen) buf >>= fun () ->
  let base = Cstruct.sub buf 1 blen in
  let buf = Cstruct.shift buf (1 + blen) in
  check_length 1 buf >>= fun () ->
  let olen = Cstruct.get_uint8 buf 0 in
  check_length (1 + olen) buf >>= fun () ->
  let order = Cstruct.sub buf 1 olen in
  let buf = Cstruct.shift buf (1 + olen) in
  check_length 1 buf >>= fun () ->
  let cofactorlength = Cstruct.get_uint8 buf 0 in
  check_length (1 + cofactorlength) buf >>= fun () ->
  let cofactor = Cstruct.sub buf 1 cofactorlength in
  let buf = Cstruct.shift buf (1 + cofactorlength) in
  check_length 1 buf >>= fun () ->
  let publiclen = Cstruct.get_uint8 buf 0 in
  check_length (1 + publiclen) buf >>= fun () ->
  let public = Cstruct.sub buf 1 publiclen in
  let buf = Cstruct.shift buf (1 + publiclen) in
  return ({ m ; basis ; ks ; curve ; base ; order ; cofactor ; public }, buf)

let parse_ec_parameters buf =
  check_length 1 buf >>= fun () ->
  let pbuf = Cstruct.shift buf 1 in
  let typ = Cstruct.get_uint8 buf 0 in
  match int_to_ec_curve_type typ with
  | Some EXPLICIT_PRIME ->
     parse_ec_prime_parameters pbuf >>= fun (ep, buf) ->
     return (ExplicitPrimeParameters ep, buf)
  | Some EXPLICIT_CHAR2 ->
     parse_ec_char_parameters pbuf >>= fun (ec, buf) ->
     return (ExplicitCharParameters ec, buf)
  | Some NAMED_CURVE ->
     parse_named_curve pbuf >>= fun (curve) ->
     check_length 3 buf >>= fun () ->
     let plen = Cstruct.get_uint8 buf 2 in
     check_length (3 + plen) buf >>= fun () ->
     let public = Cstruct.sub buf 3 plen in
     return (NamedCurveParameters (curve, public), Cstruct.shift buf (3 + plen))
  | _ -> fail (Unknown ("curve type: " ^ string_of_int typ))

let parse_client_key_exchange buf =
  check_length 2 buf >>= fun () ->
  let len = Cstruct.BE.get_uint16 buf 0 in
  check_length (2 + len) buf >>= fun () ->
  return (ClientKeyExchange (Cstruct.sub buf 2 len))

let parse_handshake buf =
  check_length 4 buf >>= fun () ->
  let typ = Cstruct.get_uint8 buf 0 in
  let handshake_type = int_to_handshake_type typ in
  let len = get_uint24_len (Cstruct.shift buf 1) in
  check_length (4 + len) buf >>= fun () ->
  let payload = Cstruct.sub buf 4 len in
  match handshake_type with
    | Some HELLO_REQUEST -> return HelloRequest
    | Some CLIENT_HELLO -> parse_client_hello payload
    | Some SERVER_HELLO -> parse_server_hello payload
    | Some CERTIFICATE -> parse_certificates payload
    | Some SERVER_KEY_EXCHANGE -> return (ServerKeyExchange payload)
    | Some SERVER_HELLO_DONE -> return ServerHelloDone
    | Some CERTIFICATE_REQUEST -> parse_certificate_request payload
    | Some CLIENT_KEY_EXCHANGE -> parse_client_key_exchange payload
    | Some FINISHED ->
       check_length 12 payload >>= fun () ->
       return (Finished (Cstruct.sub payload 0 12))
    | _  -> fail (Unknown ("handshake type" ^ string_of_int typ))
