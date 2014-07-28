open Utils
open Core
open State

let empty = function [] -> true | _ -> false

let assure p = guard p Packet.HANDSHAKE_FAILURE

let fail_handshake = fail Packet.HANDSHAKE_FAILURE

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

let get_hostname_ext h =
  map_find
    h.extensions
    ~f:(function Hostname s -> Some s | _ -> None)

let hostname h : string option =
  match get_hostname_ext h with
  | Some (Some name) -> Some name
  | _                -> None

let get_secure_renegotiation exts =
  map_find
    exts
    ~f:(function SecureRenegotiation data -> Some data | _ -> None)

let empty_session = {
  server_random    = Cstruct.create 0 ;
  client_random    = Cstruct.create 0 ;
  client_version   = Supported TLS_1_0 ;
  ciphersuite      = `TLS_RSA_WITH_RC4_128_MD5 ;
  peer_certificate = [] ;
  own_certificate  = [] ;
  own_private_key  = None ;
  own_name         = None ;
  master_secret    = Cstruct.create 0 ;
  renegotiation    = Cstruct.(create 0, create 0) ;
}

let supported_protocol_version (min, max) v =
  match version_ge v min, version_ge v max with
    | _   , true -> Some max
    | true, _    -> any_version_to_version v
    | _   , _    -> None

let to_ext_type = function
  | Hostname _            -> `Hostname
  | MaxFragmentLength _   -> `MaxFragmentLength
  | EllipticCurves _      -> `EllipticCurves
  | ECPointFormats _      -> `ECPointFormats
  | SecureRenegotiation _ -> `SecureRenegotiation
  | Padding _             -> `Padding
  | SignatureAlgorithms _ -> `SignatureAlgorithms
  | UnknownExtension _    -> `UnknownExtension

let extension_types exts = List.(
  exts |> map to_ext_type
       |> filter @@ function `UnknownExtension -> false | _ -> true
  )

let not_multiple_same_extensions exts =
  List_set.is_proper_set (extension_types exts)

(* a server hello may only contain extensions which are also in the client hello *)
(*  RFC5246, 7.4.7.1
   An extension type MUST NOT appear in the ServerHello unless the same
   extension type appeared in the corresponding ClientHello.  If a
   client receives an extension type in ServerHello that it did not
   request in the associated ClientHello, it MUST abort the handshake
   with an unsupported_extension fatal alert. *)
let server_exts_subset_of_client sexts cexts =
  let (sexts', cexts') =
    (extension_types sexts, extension_types cexts) in
  List_set.subset sexts' cexts'
  &&
  let forbidden = function
    | `Padding | `SignatureAlgorithms -> true
    | _                               -> false in
  not (List.exists forbidden sexts')

let client_hello_valid ch =
  let open Ciphersuite in

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

  not (empty ch.ciphersuites)
  &&

  (List_set.is_proper_set ch.ciphersuites)
  &&

  (* TODO: if ecc ciphersuite, require ellipticcurves and ecpointformats extensions! *)
  not_multiple_same_extensions ch.extensions
  &&

  ( match ch.version with
    | Supported TLS_1_2 | TLS_1_X _                  -> true
    | SSL_3 | Supported TLS_1_0 | Supported TLS_1_1  ->
        let has_sig_algo =
          List.exists (function SignatureAlgorithms _ -> true | _ -> false)
            ch.extensions in
        not has_sig_algo )
  &&

  get_hostname_ext ch <> Some None

let server_hello_valid sh =
  let open Ciphersuite in

  not_multiple_same_extensions sh.extensions
  &&
  ( match get_hostname_ext sh with
    Some (Some _) -> false | _ -> true )
  (* TODO:
      - EC stuff must be present if EC ciphersuite chosen
   *)
