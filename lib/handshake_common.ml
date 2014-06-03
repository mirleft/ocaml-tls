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
  | (Hostname _)::(Hostname _)::xs -> fail Packet.HANDSHAKE_FAILURE
  | (Hostname _)::xs -> not_multiple_same_extensions xs
  | (MaxFragmentLength _)::(MaxFragmentLength _)::xs -> fail Packet.HANDSHAKE_FAILURE
  | (MaxFragmentLength _)::xs -> not_multiple_same_extensions xs
  | (EllipticCurves _)::(EllipticCurves _)::xs -> fail Packet.HANDSHAKE_FAILURE
  | (EllipticCurves _)::xs -> not_multiple_same_extensions xs
  | (ECPointFormats _)::(ECPointFormats _)::xs -> fail Packet.HANDSHAKE_FAILURE
  | (ECPointFormats _)::xs -> not_multiple_same_extensions xs
  | (SecureRenegotiation _)::(SecureRenegotiation _)::xs -> fail Packet.HANDSHAKE_FAILURE
  | (SecureRenegotiation _)::xs -> not_multiple_same_extensions xs
  | (Padding _)::(Padding _)::xs -> fail Packet.HANDSHAKE_FAILURE
  | (Padding _)::xs -> not_multiple_same_extensions xs
  | (SignatureAlgorithms _)::(SignatureAlgorithms _)::xs -> fail Packet.HANDSHAKE_FAILURE
  | (SignatureAlgorithms _)::xs -> not_multiple_same_extensions xs
  | (UnknownExtension _)::xs -> not_multiple_same_extensions xs
  | [] -> return ()

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
  | [], [] -> return ()
  | _, _ -> fail Packet.HANDSHAKE_FAILURE


let rec check_not_null = function
  | []    -> return ()
  | c::cs -> Ciphersuite.(match get_kex_enc_hash c with
                          | NULL, _, _ -> fail Packet.HANDSHAKE_FAILURE
                          | _, NULL, _ -> fail Packet.HANDSHAKE_FAILURE
                          | _, _, NULL -> fail Packet.HANDSHAKE_FAILURE
                          | _, _, _    -> check_not_null cs)

let validate_client_hello ch =
  let open Packet in
  let open Ciphersuite in
  let rec check_duplicate_ciphersuites = function
    | []                       -> return ()
    | f::rt when List.mem f rt -> fail HANDSHAKE_FAILURE
    | _::rt                    -> check_duplicate_ciphersuites rt
  in

  (* match ch.version with
    | TLS_1_0 ->
       if List.mem TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA ch.ciphersuites then
         return ()
       else
         fail HANDSHAKE_FAILURE
    | TLS_1_1 ->
       if List.mem TLS_RSA_WITH_3DES_EDE_CBC_SHA ch.ciphersuites then
         return ()
       else
         fail HANDSHAKE_FAILURE
    | TLS_1_2 ->
       if List.mem TLS_RSA_WITH_AES_128_CBC_SHA ch.ciphersuites then
         return ()
       else
         fail HANDSHAKE_FAILURE *)

  (if List.length ch.ciphersuites = 0 then fail HANDSHAKE_FAILURE else return ()) >>= fun () ->
  check_duplicate_ciphersuites ch.ciphersuites >>= fun () ->
  let ciphers_no_reneg =
    List.filter (fun c -> not (c = TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
                ch.ciphersuites
  in
  check_not_null ciphers_no_reneg >>= fun () ->

  (* TODO: if ecc ciphersuite, require ellipticcurves and ecpointformats extensions! *)
  not_multiple_same_extensions (List.sort compare ch.extensions) >>= fun () ->

  let sigs = map_find
               ch.extensions
               ~f:(function SignatureAlgorithms s -> Some s | _ -> None)
  in
  ( match ch.version, sigs with
    | TLS_1_0, Some _ | TLS_1_1, Some _ -> fail HANDSHAKE_FAILURE
    | _ , _ -> return ()
  ) >>= fun () ->

  let servername = get_hostname_ext ch in
  match servername with
  | Some None -> fail HANDSHAKE_FAILURE
  | _ -> return ()

let validate_server_hello sh =
  ( if sh.ciphersuites = Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV then
      fail Packet.HANDSHAKE_FAILURE
    else
      return ()
  ) >>= fun () ->

  check_not_null [sh.ciphersuites] >>= fun () ->

  not_multiple_same_extensions sh.extensions >>= fun () ->

  let servername = get_hostname_ext sh in
    match servername with
    | Some (Some _) -> fail Packet.HANDSHAKE_FAILURE
    | _ -> return ()
  (* TODO:
      - EC stuff must be present if EC ciphersuite chosen
   *)

