(** Core type definitions *)

open Packet
open Ciphersuite

let (<+>) = Cstruct.append

let ( let* ) = Result.bind

let guard p e = if p then Ok () else Error e

let map_reader_error r = Result.map_error (fun re -> `Fatal (`ReaderError re)) r

type tls13 = [ `TLS_1_3 ]

let pp_tls13 ppf `TLS_1_3 = Fmt.string ppf "TLS 1.3"

type tls_before_13 = [
  | `TLS_1_0
  | `TLS_1_1
  | `TLS_1_2
]

let pp_tls_before_13 ppf = function
  | `TLS_1_0 -> Fmt.string ppf "TLS 1.0"
  | `TLS_1_1 -> Fmt.string ppf "TLS 1.1"
  | `TLS_1_2 -> Fmt.string ppf "TLS 1.2"

type tls_version = [ tls13 | tls_before_13 ]

let pp_tls_version ppf = function
  | #tls13 as v -> pp_tls13 ppf v
  | #tls_before_13 as v -> pp_tls_before_13 ppf v

let pair_of_tls_version = function
  | `TLS_1_0   -> (3, 1)
  | `TLS_1_1   -> (3, 2)
  | `TLS_1_2   -> (3, 3)
  | `TLS_1_3   -> (3, 4)

let compare_tls_version a b = match a, b with
  | `TLS_1_0, `TLS_1_0 -> 0 | `TLS_1_0, _ -> -1 | _, `TLS_1_0 -> 1
  | `TLS_1_1, `TLS_1_1 -> 0 | `TLS_1_1, _ -> -1 | _, `TLS_1_1 -> 1
  | `TLS_1_2, `TLS_1_2 -> 0 | `TLS_1_2, _ -> -1 | _, `TLS_1_2 -> 1
  | `TLS_1_3, `TLS_1_3 -> 0

let next = function
  | `TLS_1_0 -> Some `TLS_1_1
  | `TLS_1_1 -> Some `TLS_1_2
  | `TLS_1_2 -> Some `TLS_1_3
  | `TLS_1_3 -> None

let all_versions (min, max) =
  let rec gen curr =
    if compare_tls_version max curr >= 0 then
      match next curr with
      | None -> [curr]
      | Some c -> curr :: gen c
    else
      []
  in
  List.rev (gen min)

let tls_version_of_pair = function
  | (3, 1) -> Some `TLS_1_0
  | (3, 2) -> Some `TLS_1_1
  | (3, 3) -> Some `TLS_1_2
  | (3, 4) -> Some `TLS_1_3
  | _      -> None

type tls_any_version = [
  | tls_version
  | `SSL_3
  | `TLS_1_X of int
]

let pp_tls_any_version ppf = function
  | #tls_version as v -> pp_tls_version ppf v
  | `SSL_3 -> Fmt.string ppf "SSL3"
  | `TLS_1_X x -> Fmt.pf ppf "TLS1.%u" x

let any_version_to_version = function
  | #tls_version as v -> Some v
  | _ -> None

let version_eq a b =
  match a with
  | #tls_version as x -> compare_tls_version x b = 0
  | _ -> false

let version_ge a b =
  match a with
  | #tls_version as x -> compare_tls_version x b >= 0
  | `SSL_3 -> false
  | `TLS_1_X _ -> true

let tls_any_version_of_pair x =
  match tls_version_of_pair x with
  | Some v -> Some v
  | None ->
     match x with
     | (3, 0) -> Some `SSL_3
     | (3, x) -> Some (`TLS_1_X x)
     | _      -> None

let pair_of_tls_any_version = function
  | #tls_version as x -> pair_of_tls_version x
  | `SSL_3 -> (3, 0)
  | `TLS_1_X m -> (3, m)

let max_protocol_version (_, hi) = hi
let min_protocol_version (lo, _) = lo

type tls_hdr = {
  content_type : content_type;
  version      : tls_any_version;
}

let pp_tls_hdr ppf { content_type ; version } =
  Fmt.pf ppf "content type: %a version: %a" pp_content_type content_type
    pp_tls_any_version version

module SessionID = struct
  type t = Cstruct.t
  let compare = Cstruct.compare
  let hash t = Hashtbl.hash (Cstruct.to_bigarray t)
  let equal = Cstruct.equal
end

module PreSharedKeyID = struct
  type t = Cstruct.t
  let compare = Cstruct.compare
  let hash t = Hashtbl.hash (Cstruct.to_bigarray t)
  let equal = Cstruct.equal
end

type psk_identity = (Cstruct.t * int32) * Cstruct.t

let binders_len psks =
  let binder_len (_, binder) =
    Cstruct.length binder + 1 (* binder len *)
  in
  2 (* binder len *) + List.fold_left (+) 0 (List.map binder_len psks)

type group = [
  | `FFDHE2048
  | `FFDHE3072
  | `FFDHE4096
  | `FFDHE6144
  | `FFDHE8192
  | `X25519
  | `P256
  | `P384
  | `P521
]

let pp_group ppf = function
  | `FFDHE2048 -> Fmt.string ppf "FFDHE2048"
  | `FFDHE3072 -> Fmt.string ppf "FFDHE3072"
  | `FFDHE4096 -> Fmt.string ppf "FFDHE4096"
  | `FFDHE6144 -> Fmt.string ppf "FFDHE6144"
  | `FFDHE8192 -> Fmt.string ppf "FFDHE8192"
  | `X25519 -> Fmt.string ppf "X25519"
  | `P256 -> Fmt.string ppf "P256"
  | `P384 -> Fmt.string ppf "P384"
  | `P521 -> Fmt.string ppf "P521"

let named_group_to_group = function
  | FFDHE2048 -> Some `FFDHE2048
  | FFDHE3072 -> Some `FFDHE3072
  | FFDHE4096 -> Some `FFDHE4096
  | FFDHE6144 -> Some `FFDHE6144
  | FFDHE8192 -> Some `FFDHE8192
  | X25519 -> Some `X25519
  | SECP256R1 -> Some `P256
  | SECP384R1 -> Some `P384
  | SECP521R1 -> Some `P521
  | _ -> None

let group_to_named_group = function
  | `FFDHE2048 -> FFDHE2048
  | `FFDHE3072 -> FFDHE3072
  | `FFDHE4096 -> FFDHE4096
  | `FFDHE6144 -> FFDHE6144
  | `FFDHE8192 -> FFDHE8192
  | `X25519 -> X25519
  | `P256 -> SECP256R1
  | `P384 -> SECP384R1
  | `P521 -> SECP521R1

let group_to_impl = function
  | `FFDHE2048 -> `Finite_field Mirage_crypto_pk.Dh.Group.ffdhe2048
  | `FFDHE3072 -> `Finite_field Mirage_crypto_pk.Dh.Group.ffdhe3072
  | `FFDHE4096 -> `Finite_field Mirage_crypto_pk.Dh.Group.ffdhe4096
  | `FFDHE6144 -> `Finite_field Mirage_crypto_pk.Dh.Group.ffdhe6144
  | `FFDHE8192 -> `Finite_field Mirage_crypto_pk.Dh.Group.ffdhe8192
  | `X25519 -> `X25519
  | `P256 -> `P256
  | `P384 -> `P384
  | `P521 -> `P521

type signature_algorithm = [
  | `RSA_PKCS1_MD5
  | `RSA_PKCS1_SHA1
  | `RSA_PKCS1_SHA224
  | `RSA_PKCS1_SHA256
  | `RSA_PKCS1_SHA384
  | `RSA_PKCS1_SHA512
  | `ECDSA_SECP256R1_SHA1
  | `ECDSA_SECP256R1_SHA256
  | `ECDSA_SECP384R1_SHA384
  | `ECDSA_SECP521R1_SHA512
  | `RSA_PSS_RSAENC_SHA256
  | `RSA_PSS_RSAENC_SHA384
  | `RSA_PSS_RSAENC_SHA512
  | `ED25519
(*  | `ED448
  | `RSA_PSS_PSS_SHA256
  | `RSA_PSS_PSS_SHA384
    | `RSA_PSS_PSS_SHA512 *)
]

let hash_of_signature_algorithm = function
  | `RSA_PKCS1_MD5 -> `MD5
  | `RSA_PKCS1_SHA1 -> `SHA1
  | `RSA_PKCS1_SHA224 -> `SHA224
  | `RSA_PKCS1_SHA256 -> `SHA256
  | `RSA_PKCS1_SHA384 -> `SHA384
  | `RSA_PKCS1_SHA512 -> `SHA512
  | `RSA_PSS_RSAENC_SHA256 -> `SHA256
  | `RSA_PSS_RSAENC_SHA384 -> `SHA384
  | `RSA_PSS_RSAENC_SHA512 -> `SHA512
  | `ECDSA_SECP256R1_SHA1 -> `SHA1
  | `ECDSA_SECP256R1_SHA256 -> `SHA256
  | `ECDSA_SECP384R1_SHA384 -> `SHA384
  | `ECDSA_SECP521R1_SHA512 -> `SHA512
  | `ED25519 -> `SHA512

let signature_scheme_of_signature_algorithm = function
  | `RSA_PKCS1_MD5 -> `RSA_PKCS1
  | `RSA_PKCS1_SHA1 -> `RSA_PKCS1
  | `RSA_PKCS1_SHA224 -> `RSA_PKCS1
  | `RSA_PKCS1_SHA256 -> `RSA_PKCS1
  | `RSA_PKCS1_SHA384 -> `RSA_PKCS1
  | `RSA_PKCS1_SHA512 -> `RSA_PKCS1
  | `RSA_PSS_RSAENC_SHA256 -> `RSA_PSS
  | `RSA_PSS_RSAENC_SHA384 -> `RSA_PSS
  | `RSA_PSS_RSAENC_SHA512 -> `RSA_PSS
  | `ECDSA_SECP256R1_SHA1 -> `ECDSA
  | `ECDSA_SECP256R1_SHA256 -> `ECDSA
  | `ECDSA_SECP384R1_SHA384 -> `ECDSA
  | `ECDSA_SECP521R1_SHA512 -> `ECDSA
  | `ED25519 -> `ED25519

let pp_signature_algorithm ppf sa =
  let h = hash_of_signature_algorithm sa
  and ss = signature_scheme_of_signature_algorithm sa
  in
  let pp_signature_scheme ppf = function
    | `RSA_PKCS1 -> Fmt.string ppf "RSA-PKCS1"
    | `RSA_PSS -> Fmt.string ppf "RSA-PSS"
    | `ECDSA -> Fmt.string ppf "ECDSA"
    | `ED25519 -> Fmt.string ppf "ED25519"
  in
  match ss with
  | `ED25519 -> Fmt.pf ppf "%a" pp_signature_scheme ss
  | `ECDSA ->
    let group_to_string = function
      | `ECDSA_SECP256R1_SHA1 -> "SECP256R1"
      | `ECDSA_SECP256R1_SHA256 -> "SECP256R1"
      | `ECDSA_SECP384R1_SHA384 -> "SECP384R1"
      | `ECDSA_SECP521R1_SHA512 -> "SECP521R1"
      | _ -> assert false
    in
    Fmt.pf ppf "%a %s %a" pp_signature_scheme ss (group_to_string sa) pp_hash h
  | _ -> Fmt.pf ppf "%a %a" pp_signature_scheme ss pp_hash h

let rsa_sigalg = function
  | `RSA_PSS_RSAENC_SHA256 | `RSA_PSS_RSAENC_SHA384 | `RSA_PSS_RSAENC_SHA512
  | `RSA_PKCS1_SHA256 | `RSA_PKCS1_SHA384 | `RSA_PKCS1_SHA512
  | `RSA_PKCS1_SHA224 | `RSA_PKCS1_SHA1 | `RSA_PKCS1_MD5 -> true
  | `ECDSA_SECP256R1_SHA1 | `ECDSA_SECP256R1_SHA256 | `ECDSA_SECP384R1_SHA384
  | `ECDSA_SECP521R1_SHA512 | `ED25519 -> false

let tls13_sigalg = function
  | `RSA_PSS_RSAENC_SHA256 | `RSA_PSS_RSAENC_SHA384 | `RSA_PSS_RSAENC_SHA512
  | `ECDSA_SECP256R1_SHA256 | `ECDSA_SECP384R1_SHA384
  | `ECDSA_SECP521R1_SHA512 | `ED25519 -> true
  | `RSA_PKCS1_SHA256 | `RSA_PKCS1_SHA384 | `RSA_PKCS1_SHA512
  | `RSA_PKCS1_SHA224 | `RSA_PKCS1_SHA1 | `RSA_PKCS1_MD5
  | `ECDSA_SECP256R1_SHA1 -> false

let pk_matches_sa pk sa =
  match pk, sa with
  | `RSA _, _ -> rsa_sigalg sa
  | `ED25519 _, `ED25519
  | `P256 _, (`ECDSA_SECP256R1_SHA1 | `ECDSA_SECP256R1_SHA256)
  | `P384 _, `ECDSA_SECP384R1_SHA384
  | `P521 _, `ECDSA_SECP521R1_SHA512 -> true
  | _ -> false

type client_extension = [
  | `Hostname of [`host] Domain_name.t
  | `MaxFragmentLength of max_fragment_length
  | `SupportedGroups of Packet.named_group list
  | `SecureRenegotiation of Cstruct.t
  | `Padding of int
  | `SignatureAlgorithms of signature_algorithm list
  | `ExtendedMasterSecret
  | `ALPN of string list
  | `KeyShare of (Packet.named_group * Cstruct.t) list
  | `EarlyDataIndication
  | `PreSharedKeys of psk_identity list
  | `SupportedVersions of tls_any_version list
  | `PostHandshakeAuthentication
  | `Cookie of Cstruct.t
  | `PskKeyExchangeModes of psk_key_exchange_mode list
  | `ECPointFormats
  | `UnknownExtension of (int * Cstruct.t)
]

type server13_extension = [
  | `KeyShare of (group * Cstruct.t)
  | `PreSharedKey of int
  | `SelectedVersion of tls_version (* only used internally in writer!! *)
]

type server_extension = [
  server13_extension
  | `Hostname
  | `MaxFragmentLength of max_fragment_length
  | `SecureRenegotiation of Cstruct.t
  | `ExtendedMasterSecret
  | `ALPN of string
  | `ECPointFormats
  | `UnknownExtension of (int * Cstruct.t)
]

type encrypted_extension = [
  | `Hostname
  | `MaxFragmentLength of max_fragment_length
  | `SupportedGroups of group list
  | `ALPN of string
  | `EarlyDataIndication
  | `UnknownExtension of (int * Cstruct.t)
]

type hello_retry_extension = [
  | `SelectedGroup of group (* only used internally in writer!! *)
  | `Cookie of Cstruct.t
  | `SelectedVersion of tls_version (* only used internally in writer!! *)
  | `UnknownExtension of (int * Cstruct.t)
]

type client_hello = {
  client_version : tls_any_version;
  client_random  : Cstruct.t;
  sessionid      : SessionID.t option;
  ciphersuites   : any_ciphersuite list;
  extensions     : client_extension list
}

type server_hello = {
  server_version : tls_version;
  server_random  : Cstruct.t;
  sessionid      : SessionID.t option;
  ciphersuite    : ciphersuite;
  extensions     : server_extension list
}

type dh_parameters = {
  dh_p  : Cstruct.t;
  dh_g  : Cstruct.t;
  dh_Ys : Cstruct.t;
}

type hello_retry = {
  retry_version : tls_version ;
  ciphersuite : ciphersuite13 ;
  sessionid : SessionID.t option ;
  selected_group : group ;
  extensions : hello_retry_extension list
}

type session_ticket_extension = [
  | `EarlyDataIndication of int32
  | `UnknownExtension of int * Cstruct.t
]

type session_ticket = {
  lifetime : int32 ;
  age_add : int32 ;
  nonce : Cstruct.t ;
  ticket : Cstruct.t ;
  extensions : session_ticket_extension list
}

type certificate_request_extension = [
  (*  | `StatusRequest *)
  | `SignatureAlgorithms of signature_algorithm list
  (* | `SignedCertificateTimestamp *)
  | `CertificateAuthorities of X509.Distinguished_name.t list
  (* | `OidFilters *)
  (* | `SignatureAlgorithmsCert *)
  | `UnknownExtension of (int * Cstruct.t)
]

type tls_handshake =
  | HelloRequest
  | HelloRetryRequest of hello_retry
  | EncryptedExtensions of encrypted_extension list
  | ServerHelloDone
  | ClientHello of client_hello
  | ServerHello of server_hello
  | Certificate of Cstruct.t
  | ServerKeyExchange of Cstruct.t
  | CertificateRequest of Cstruct.t
  | ClientKeyExchange of Cstruct.t
  | CertificateVerify of Cstruct.t
  | Finished of Cstruct.t
  | SessionTicket of session_ticket
  | KeyUpdate of key_update_request_type
  | EndOfEarlyData

let pp_handshake ppf = function
  | HelloRequest -> Fmt.string ppf "HelloRequest"
  | HelloRetryRequest _ -> Fmt.string ppf "HelloRetryRequest"
  | EncryptedExtensions _ -> Fmt.string ppf "EncryptedExtensions"
  | ServerHelloDone -> Fmt.string ppf "ServerHelloDone"
  | ClientHello _ -> Fmt.string ppf "ClientHello"
  | ServerHello _ -> Fmt.string ppf "ServerHello"
  | Certificate _ -> Fmt.string ppf "Certificate"
  | ServerKeyExchange _ -> Fmt.string ppf "ServerKeyExchange"
  | CertificateRequest _ -> Fmt.string ppf "CertificateRequest"
  | ClientKeyExchange _ -> Fmt.string ppf "ClientKeyExchange"
  | CertificateVerify _ -> Fmt.string ppf "CertificateVerify"
  | Finished _ -> Fmt.string ppf "Finished"
  | SessionTicket _ -> Fmt.string ppf "SessionTicket"
  | KeyUpdate _ -> Fmt.string ppf "KeyUpdate"
  | EndOfEarlyData -> Fmt.string ppf "EndOfEarlyData"

let src = Logs.Src.create "tls.tracing" ~doc:"TLS tracing"
module Tracing = struct
  include (val Logs.src_log src : Logs.LOG)
  let cs ~tag buf = debug (fun m -> m "%s@.%a" tag Cstruct.hexdump_pp buf)
  let hs ~tag hs = debug (fun m -> m "%s %a" tag pp_handshake hs)
end

type tls_alert = alert_level * alert_type

(** the master secret of a TLS connection *)
type master_secret = Cstruct.t

type psk13 = {
  identifier : Cstruct.t ;
  obfuscation : int32 ;
  secret : Cstruct.t ;
  lifetime : int32 ;
  early_data : int32 ;
  issued_at : Ptime.t ;
  (* origin : [ `Resumption | `External ] (* using different labels for binder_key *) *)
}

type epoch_state = [ `ZeroRTT | `Established ]

(** information about an open session *)
type epoch_data = {
  state                  : epoch_state ;
  protocol_version       : tls_version ;
  ciphersuite            : Ciphersuite.ciphersuite ;
  peer_random            : Cstruct.t ;
  peer_certificate_chain : X509.Certificate.t list ;
  peer_certificate       : X509.Certificate.t option ;
  peer_name              : [`host] Domain_name.t option ;
  trust_anchor           : X509.Certificate.t option ;
  received_certificates  : X509.Certificate.t list ;
  own_random             : Cstruct.t ;
  own_certificate        : X509.Certificate.t list ;
  own_private_key        : X509.Private_key.t option ;
  own_name               : [`host] Domain_name.t option ;
  master_secret          : master_secret ;
  session_id             : SessionID.t ;
  extended_ms            : bool ;
  alpn_protocol          : string option ;
}

let supports_key_usage ?(not_present = false) usage cert =
  match X509.Extension.(find Key_usage (X509.Certificate.extensions cert)) with
  | None -> not_present
  | Some (_, kus) -> List.mem usage kus

let supports_extended_key_usage ?(not_present = false) usage cert =
  match X509.Extension.(find Ext_key_usage (X509.Certificate.extensions cert)) with
  | None -> not_present
  | Some (_, kus) -> List.mem usage kus
