open Utils
open Core

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

let get_hostname_ext h =
  map_find
    h.extensions
    ~f:(function Hostname s -> Some s | _ -> None)

let find_hostname : 'a hello -> string option =
  fun h ->
    match get_hostname_ext h with
    | Some (Some name) -> Some name
    | _                -> None

let get_secure_renegotiation exts =
  map_find
    exts
    ~f:(function SecureRenegotiation data -> Some data | _ -> None)

let supported_protocol_version (max, min) v =
  match v >= max, v >= min with
    | true, _    -> Some max
    | _   , true -> Some v
    | _   , _    -> None

let rec not_multiple_same_extensions = function
  | (Hostname _)::(Hostname _)::xs -> invalid_arg "multiple hostname extensions"
  | (Hostname _)::xs -> not_multiple_same_extensions xs
  | (MaxFragmentLength _)::(MaxFragmentLength _)::xs -> invalid_arg "multiple maxfragmentlength extensions"
  | (MaxFragmentLength _)::xs -> not_multiple_same_extensions xs
  | (EllipticCurves _)::(EllipticCurves _)::xs -> invalid_arg "multiple ellipticcurve extensions"
  | (EllipticCurves _)::xs -> not_multiple_same_extensions xs
  | (ECPointFormats _)::(ECPointFormats _)::xs -> invalid_arg "multiple elliptic curve format extensions"
  | (ECPointFormats _)::xs -> not_multiple_same_extensions xs
  | (SecureRenegotiation _)::(SecureRenegotiation _)::xs -> invalid_arg "multiple secure renegotiation extensions"
  | (SecureRenegotiation _)::xs -> not_multiple_same_extensions xs
  | (Padding _)::(Padding _)::xs -> invalid_arg "multiple padding extensions"
  | (Padding _)::xs -> not_multiple_same_extensions xs
  | (SignatureAlgorithms _)::(SignatureAlgorithms _)::xs -> invalid_arg "multiple signaturealgorithms extensions"
  | (SignatureAlgorithms _)::xs -> not_multiple_same_extensions xs
  | (UnknownExtension _)::xs -> not_multiple_same_extensions xs
  | [] -> ()

(* a server hello may only contain extensions which are also in the client hello *)
(*  RFC5246, 7.4.7.1
   An extension type MUST NOT appear in the ServerHello unless the same
   extension type appeared in the corresponding ClientHello.  If a
   client receives an extension type in ServerHello that it did not
   request in the associated ClientHello, it MUST abort the handshake
   with an unsupported_extension fatal alert. *)
let rec server_exts_subset_of_client sexts cexts =
  match sexts, cexts with
  | (Hostname _)::ses, (Hostname _)::ces -> server_exts_subset_of_client ses ces
  | ses, (Hostname _)::ces -> server_exts_subset_of_client ses ces
  | (MaxFragmentLength _)::ses, (MaxFragmentLength _)::ces -> server_exts_subset_of_client ses ces
  | ses, (MaxFragmentLength _)::ces -> server_exts_subset_of_client ses ces
  | (EllipticCurves _)::ses, (EllipticCurves _)::ces -> server_exts_subset_of_client ses ces
  | ses, (EllipticCurves _)::ces -> server_exts_subset_of_client ses ces
  | (ECPointFormats _)::ses, (ECPointFormats _)::ces -> server_exts_subset_of_client ses ces
  | ses, (ECPointFormats _)::ces -> server_exts_subset_of_client ses ces
  | (SecureRenegotiation _)::ses, (SecureRenegotiation _)::ces -> server_exts_subset_of_client ses ces
  | ses, (SecureRenegotiation _)::ces -> server_exts_subset_of_client ses ces
  | ses, (Padding _)::ces -> server_exts_subset_of_client ses ces
  | ses, (SignatureAlgorithms _)::ces -> server_exts_subset_of_client ses ces
  | (UnknownExtension _)::ses, ces -> server_exts_subset_of_client ses ces
  | ses, (UnknownExtension _)::ces -> server_exts_subset_of_client ses ces
  | [], [] -> ()
  | _, _ -> invalid_arg "server extensions not subset of client extensions"


let rec check_not_null = function
  | []    -> ()
  | c::cs -> match Ciphersuite.get_kex_enc_hash c with
              | NULL, _, _ -> Printf.printf "kex null\n" ; invalid_arg "kex is NULL"
              | _, NULL, _ -> Printf.printf "enc null\n" ; invalid_arg "encryption algorithm is NULL"
              | _, _, NULL -> Printf.printf "hash null\n" ; invalid_arg "hash algorithm is NULL"
              | _, _, _    -> check_not_null cs

let validate_client_hello ch =
  ( if List.length ch.ciphersuites = 0 then
      invalid_arg "empty ciphersuites list" ) ;
  let rec check = function
    | []    -> ()
    | f::rt ->
       if List.mem f rt then
         invalid_arg "duplicated ciphersuite"
       else
         check rt
  in
  check ch.ciphersuites ;

  check_not_null (List.filter
                    (fun c -> not (c = Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
                    ch.ciphersuites) ;

  (* TODO: if ecc ciphersuite, require ellipticcurves and ecpointformats extensions! *)
(*  ( match ch.version with
    | TLS_1_0 ->
       if not (List.mem Ciphersuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA ch.ciphersuites) then
         invalid_arg "missing mandatory ciphersuite for TLS 1.0"
    | TLS_1_1 ->
       if not (List.mem Ciphersuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA ch.ciphersuites) then
         invalid_arg "missing mandatory ciphersuite for TLS 1.1"
    | TLS_1_2 ->
       if not (List.mem Ciphersuite.TLS_RSA_WITH_AES_128_CBC_SHA ch.ciphersuites) then
         invalid_arg "missing mandatory ciphersuite for TLS 1.2" ) ; *)

  not_multiple_same_extensions (List.sort compare ch.extensions) ;

  let sigs = map_find
               ch.extensions
               ~f:(function SignatureAlgorithms s -> Some s | _ -> None)
  in
  ( match ch.version, sigs with
    | TLS_1_0, Some _ | TLS_1_1, Some _ -> invalid_arg "unexpected signature algorithm extension"
    | _ , _ -> () ) ;

  let servername = get_hostname_ext ch in
  match servername with
  | Some None -> invalid_arg "empty servername in client hello"
  | _ -> ()

let validate_server_hello sh =
  ( if sh.ciphersuites = Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV then
      invalid_arg "ciphersuite should not be selected" ) ;

  check_not_null [sh.ciphersuites] ;

  not_multiple_same_extensions sh.extensions ;

  let servername = get_hostname_ext sh in
    match servername with
    | Some (Some _) -> invalid_arg "non-empty servername in server hello"
    | _ -> ()
  (* TODO:
      - EC stuff must be present if EC ciphersuite chosen
   *)

(* TODO: *)
let validate_dh_params dh =
  (* public parameter should be >= 2 and also <= p - 2 *)
  true

