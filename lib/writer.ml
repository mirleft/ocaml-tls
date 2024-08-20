open Packet
open Core

let assemble_protocol_version_int buf off version =
  let major, minor = pair_of_tls_version version in
  Bytes.set_uint8 buf off major;
  Bytes.set_uint8 buf (off + 1) minor

let assemble_protocol_version ?(buf= Bytes.create 2) version =
  assemble_protocol_version_int buf 0 version;
  Bytes.unsafe_to_string buf

let assemble_any_protocol_version_into buf off version =
  let major, minor = pair_of_tls_any_version version in
  Bytes.set_uint8 buf off major;
  Bytes.set_uint8 buf (off + 1) minor

let assemble_any_protocol_version version =
  let buf = Bytes.create 2 in
  assemble_any_protocol_version_into buf 0 version;
  Bytes.unsafe_to_string buf

let assemble_hdr version (content_type, payload) =
  let buf = Bytes.create 5 in
  Bytes.set_uint8 buf 0 (content_type_to_int content_type);
  assemble_protocol_version_int buf 1 version;
  Bytes.set_uint16_be buf 3 (String.length payload);
  Bytes.unsafe_to_string buf ^ payload

type len = One | Two | Three

let assemble_list ?none_if_empty lenb f elements =
  let length body =
    match lenb with
    | One   ->
       let l = Bytes.create 1 in
       Bytes.set_uint8 l 0 (String.length body) ;
       Bytes.unsafe_to_string l
    | Two   ->
       let l = Bytes.create 2 in
       Bytes.set_uint16_be l 0 (String.length body) ;
       Bytes.unsafe_to_string l
    | Three ->
       let l = Bytes.create 3 in
       set_uint24_len ~off:0 l (String.length body) ;
       Bytes.unsafe_to_string l
  in
  let b es = String.concat "" (List.map f es) in
  let full es =
    let body = b es in
    length body ^ body
  in
  match none_if_empty with
  | Some _ -> (match elements with
               | []   -> ""
               | eles -> full eles)
  | None   -> full elements

let assemble_certificate c =
  let length = String.length c in
  let buf = Bytes.create 3 in
  set_uint24_len ~off:0 buf length;
  Bytes.unsafe_to_string buf ^ c

let assemble_certificates cs =
  assemble_list Three assemble_certificate cs

let assemble_compression_method m =
  String.make 1 (Char.unsafe_chr (compression_method_to_int m))

let assemble_compression_methods ms =
  assemble_list One assemble_compression_method ms

let assemble_any_ciphersuite c =
  let buf = Bytes.create 2 in
  Bytes.set_uint16_be buf 0 (any_ciphersuite_to_int c);
  Bytes.unsafe_to_string buf

let assemble_any_ciphersuites cs =
  assemble_list Two assemble_any_ciphersuite cs

let assemble_ciphersuite c =
  let acs = Ciphersuite.ciphersuite_to_any_ciphersuite c in
  assemble_any_ciphersuite acs

let assemble_hostname host =
  let host = Domain_name.to_string host in
  (* 8 bit hostname type; 16 bit length; value *)
  let vallength = String.length host in
  let buf = Bytes.create 3 in
  Bytes.set_uint8 buf 0 0; (* type, only 0 registered *)
  Bytes.set_uint16_be buf 1 vallength;
  Bytes.unsafe_to_string buf ^ host

let assemble_hostnames hosts =
  assemble_list Two assemble_hostname hosts

let assemble_hash_signature sigalg =
  let buf = Bytes.create 2 in
  Bytes.set_uint16_be buf 0 (signature_alg_to_int (to_signature_alg sigalg)) ;
  Bytes.unsafe_to_string buf

let assemble_signature_algorithms s =
  assemble_list Two assemble_hash_signature s

let assemble_certificate_types ts =
  let ass x =
    String.make 1 (Char.unsafe_chr (client_certificate_type_to_int x))
  in
  assemble_list One ass ts

let assemble_cas cas =
  let ass x =
    let buf = Bytes.create 2 in
    Bytes.set_uint16_be buf 0 (String.length x) ;
    Bytes.unsafe_to_string buf ^ x
  in
  assemble_list Two ass cas

let assemble_certificate_request ts cas =
  assemble_certificate_types ts ^ assemble_cas cas

let assemble_certificate_request_1_2 ts sigalgs cas =
  String.concat "" [
    assemble_certificate_types ts;
    assemble_signature_algorithms sigalgs;
    assemble_cas cas
  ]

let assemble_named_group g =
  let buf = Bytes.create 2 in
  Bytes.set_uint16_be buf 0 (named_group_to_int g);
  Bytes.unsafe_to_string buf

let assemble_group g =
  assemble_named_group (group_to_named_group g)

let assemble_supported_groups groups =
  assemble_list Two assemble_named_group groups

let assemble_keyshare_entry (ng, ks) =
  let g = assemble_named_group ng in
  let l = Bytes.create 2 in
  Bytes.set_uint16_be l 0 (String.length ks) ;
  String.concat "" [ g ; Bytes.unsafe_to_string l ; ks ]

let assemble_psk_id (id, age) =
  let id_len = Bytes.create 2 in
  Bytes.set_uint16_be id_len 0 (String.length id) ;
  let age_buf = Bytes.create 4 in
  Bytes.set_int32_be age_buf 0 age ;
  String.concat "" [ Bytes.unsafe_to_string id_len ; id ; Bytes.unsafe_to_string age_buf ]

let assemble_binder b =
  let b_len = String.make 1 (Char.unsafe_chr (String.length b)) in
  b_len ^ b

let assemble_client_psks psks =
  let ids, binders = List.split psks in
  let ids_buf = assemble_list Two assemble_psk_id ids in
  let binders_buf = assemble_list Two assemble_binder binders in
  ids_buf ^ binders_buf

let assemble_alpn_protocol p =
  let buf = String.make 1 (Char.unsafe_chr (String.length p)) in
  buf ^ p

let assemble_alpn_protocols protocols =
  assemble_list Two assemble_alpn_protocol protocols

let assemble_supported_versions vs =
  assemble_list One assemble_any_protocol_version vs

let assemble_extension = function
  | `SecureRenegotiation x ->
     let buf = String.make 1 (Char.unsafe_chr (String.length x)) in
     (buf ^ x, RENEGOTIATION_INFO)
  | `ExtendedMasterSecret -> ("", EXTENDED_MASTER_SECRET)
  | `ECPointFormats ->
    (* a list of point formats, we support type 0 = uncompressed unconditionally *)
    let data = Bytes.make 2 '\x00' in
    Bytes.set_uint8 data 0 1;
    (Bytes.unsafe_to_string data, EC_POINT_FORMATS)
  | _ -> invalid_arg "unknown extension"

let assemble_cookie c =
  let l = Bytes.create 2 in
  Bytes.set_uint16_be l 0 (String.length c) ;
  Bytes.unsafe_to_string l ^ c

let assemble_psk_key_exchange_mode mode =
  String.make 1 (Char.unsafe_chr (psk_key_exchange_mode_to_int mode))

let assemble_psk_key_exchange_modes modes =
  assemble_list One assemble_psk_key_exchange_mode modes

let assemble_ext (pay, typ) =
  let buf = Bytes.create 4 in
  Bytes.set_uint16_be buf 0 (extension_type_to_int typ);
  Bytes.set_uint16_be buf 2 (String.length pay);
  Bytes.unsafe_to_string buf ^ pay

let assemble_extensions ?none_if_empty assemble_e es =
  assemble_list ?none_if_empty Two assemble_e es

let assemble_ca ca =
  let lenbuf = Bytes.create 2 in
  let data = X509.Distinguished_name.encode_der ca in
  Bytes.set_uint16_be lenbuf 0 (String.length data) ;
  Bytes.unsafe_to_string lenbuf ^ data

let assemble_certificate_authorities cas =
  assemble_list Two assemble_ca cas

let assemble_certificate_request_extension e =
  assemble_ext @@ match e with
  | `SignatureAlgorithms s ->
    (assemble_signature_algorithms s, SIGNATURE_ALGORITHMS)
  | `CertificateAuthorities cas ->
    (assemble_certificate_authorities cas, CERTIFICATE_AUTHORITIES)
  | _ -> invalid_arg "unknown extension"

let assemble_certificate_request_1_3 ?(context = "") exts =
  let clen = String.make 1 (Char.unsafe_chr (String.length context)) in
  let exts = assemble_extensions assemble_certificate_request_extension exts in
  String.concat "" [ clen ; context ; exts ]

let assemble_client_extension e =
  assemble_ext @@ match e with
    | `SupportedGroups groups ->
      (assemble_supported_groups groups, SUPPORTED_GROUPS)
    | `Hostname name -> (assemble_hostnames [name], SERVER_NAME)
    | `Padding x -> (String.make x '\x00', PADDING)
    | `SignatureAlgorithms s ->
      (assemble_signature_algorithms s, SIGNATURE_ALGORITHMS)
    | `ALPN protocols ->
      (assemble_alpn_protocols protocols, APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
    | `KeyShare ks ->
      (assemble_list Two assemble_keyshare_entry ks, KEY_SHARE)
    | `PreSharedKeys ids ->
      (assemble_client_psks ids, PRE_SHARED_KEY)
    | `EarlyDataIndication ->
      ("", EARLY_DATA)
    | `SupportedVersions vs ->
      (assemble_supported_versions vs, SUPPORTED_VERSIONS)
    | `PostHandshakeAuthentication ->
      ("", POST_HANDSHAKE_AUTH)
    | `Cookie c ->
      (assemble_cookie c, COOKIE)
    | `PskKeyExchangeModes modes ->
      (assemble_psk_key_exchange_modes modes, PSK_KEY_EXCHANGE_MODES)
    | x -> assemble_extension x

let assemble_server_extension e =
  assemble_ext @@ match e with
    | `Hostname -> ("", SERVER_NAME)
    | `ALPN protocol ->
      (assemble_alpn_protocols [protocol], APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
    | `KeyShare (g, ks) ->
      let ng = group_to_named_group g in
      (assemble_keyshare_entry (ng, ks), KEY_SHARE)
    | `PreSharedKey id ->
      let data = Bytes.create 2 in
      Bytes.set_uint16_be data 0 id ;
      (Bytes.unsafe_to_string data, PRE_SHARED_KEY)
    | `SelectedVersion v -> (assemble_protocol_version v, SUPPORTED_VERSIONS)
    | x -> assemble_extension x

let assemble_encrypted_extension e =
  assemble_ext @@ match e with
    | `Hostname -> ("", SERVER_NAME)
    | `ALPN protocol ->
      (assemble_alpn_protocols [protocol], APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
    | `SupportedGroups groups ->
      (assemble_supported_groups (List.map group_to_named_group groups), SUPPORTED_GROUPS)
    | `EarlyDataIndication -> ("", EARLY_DATA)
    | _ -> invalid_arg "unknown extension"

let assemble_retry_extension e =
  assemble_ext @@ match e with
    | `SelectedGroup g -> (assemble_group g, KEY_SHARE)
    | `Cookie c -> (assemble_cookie c, COOKIE)
    | `SelectedVersion v -> (assemble_protocol_version v, SUPPORTED_VERSIONS)
    | `UnknownExtension _ -> invalid_arg "unknown retry extension"

let assemble_cert_ext (certificate, extensions) =
  let cert = assemble_certificate certificate
  and exts = assemble_list Two assemble_server_extension extensions
  in
  cert ^ exts

let assemble_certs_exts cs =
  assemble_list Three assemble_cert_ext cs

let assemble_certificates_1_3 context certs =
  let l = String.make 1 (Char.unsafe_chr (String.length context)) in
  String.concat "" [ l ; context ; assemble_certs_exts (List.map (fun c -> c, []) certs) ]

let assemble_sid sid =
  match sid with
  | None   -> String.make 1 '\x00'
  | Some s -> String.make 1 (Char.unsafe_chr (String.length s)) ^ s

let assemble_client_hello (cl : client_hello) : string =
  let version = match cl.client_version with
    | `TLS_1_3 -> `TLS_1_2 (* keep 0x03 0x03 on wire *)
    | x -> x
  in
  let v = assemble_any_protocol_version version in
  let sid = assemble_sid cl.sessionid in
  let css = assemble_any_ciphersuites cl.ciphersuites in
  (* compression methods, completely useless *)
  let cms = assemble_compression_methods [NULL] in
  let bbuf = String.concat "" [ v ; cl.client_random ; sid ; css ; cms ] in
  let extensions = assemble_extensions ~none_if_empty:true assemble_client_extension cl.extensions in
  (* some widely deployed firewalls drop ClientHello messages which are
     > 256 and < 511 byte, insert PADDING extension for these *)
  (* from draft-ietf-tls-padding-00:
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
  let extrapadding =
    (* since PreSharedKeys _must_ be the last extension, don't bother padding
       when it is present. rationale from ietf-tls WG
       "Padding extension and 0-RTT" thread (2016-10-30) *)
    if List.exists (function `PreSharedKeys _ -> true | _ -> false) cl.extensions then
      ""
    else
      let buflen = String.length bbuf + String.length extensions + 4 (* see above, header *) in
      if buflen >= 256 && buflen <= 511 then
        match String.length extensions with
        | 0 -> (* need to construct a 2 byte extension length as well *)
          let l = 512 (* desired length *) - 2 (* extension length *) - 4 (* padding extension header *) - buflen in
          let l = max l 0 in (* negative size is not good *)
          let padding = assemble_client_extension (`Padding l) in
          let extension_length = Bytes.create 2 in
          Bytes.set_uint16_be extension_length 0 (String.length padding);
          Bytes.unsafe_to_string extension_length ^ padding
        | _ ->
          let l = 512 - 4 (* padding extension header *) - buflen in
          let l = max l 0 in
          let padding = assemble_client_extension (`Padding l) in
          (* extensions include the 16 bit extension length field *)
          let elen = String.length extensions + String.length padding - 2 (* the 16 bit length field *) in
          Bytes.set_uint16_be (Bytes.unsafe_of_string extensions) 0 elen;
          padding
      else
        ""
  in
  String.concat "" [ bbuf ; extensions ; extrapadding ]

let assemble_server_hello (sh : server_hello) : string =
  let version, exts = match sh.server_version with
    | `TLS_1_3 -> `TLS_1_2, `SelectedVersion `TLS_1_3 :: sh.extensions
    | x -> x, sh.extensions
  in
  let v = assemble_protocol_version version in
  let sid = assemble_sid sh.sessionid in
  let cs = assemble_ciphersuite sh.ciphersuite in
  (* useless compression method *)
  let cm = assemble_compression_method NULL in
  let extensions = assemble_extensions ~none_if_empty:true assemble_server_extension exts in
  String.concat "" [ v ; sh.server_random ; sid ; cs ; cm ; extensions ]

let assemble_dh_parameters p =
  let plen, glen, yslen = (String.length p.dh_p, String.length p.dh_g, String.length p.dh_Ys) in
  let buf = Bytes.create (2 + 2 + 2 + plen + glen + yslen) in
  Bytes.set_uint16_be  buf  0 plen;
  Bytes.blit_string p.dh_p  0 buf  2 plen;
  Bytes.set_uint16_be  buf (2 + plen) glen;
  Bytes.blit_string p.dh_g  0 buf (4 + plen) glen;
  Bytes.set_uint16_be  buf (4 + plen + glen) yslen;
  Bytes.blit_string p.dh_Ys 0 buf (6 + plen + glen) yslen;
  Bytes.unsafe_to_string buf

let assemble_ec_parameters named_curve point =
  let hdr = Bytes.create 4 in
  Bytes.set_uint8 hdr 0 (ec_curve_type_to_int NAMED_CURVE);
  Bytes.set_uint16_be hdr 1 (named_group_to_int (group_to_named_group named_curve));
  Bytes.set_uint8 hdr 3 (String.length point);
  Bytes.unsafe_to_string hdr ^ point

let assemble_digitally_signed signature =
  let lenbuf = Bytes.create 2 in
  Bytes.set_uint16_be lenbuf 0 (String.length signature);
  Bytes.unsafe_to_string lenbuf ^ signature

let assemble_digitally_signed_1_2 sigalg signature =
  (assemble_hash_signature sigalg) ^ (assemble_digitally_signed signature)

let assemble_session_ticket_extension e =
  assemble_ext @@ match e with
  | `EarlyDataIndication max ->
    let buf = Bytes.create 4 in
    Bytes.set_int32_be buf 0 max ;
    (Bytes.unsafe_to_string buf, EARLY_DATA)
  | _ -> invalid_arg "unknown extension"

let assemble_session_ticket (se : session_ticket) =
  let buf = Bytes.create 9 in
  Bytes.set_int32_be buf 0 se.lifetime ;
  Bytes.set_int32_be buf 4 se.age_add ;
  Bytes.set_uint8 buf 8 (String.length se.nonce) ;
  let ticketlen = Bytes.create 2 in
  Bytes.set_uint16_be ticketlen 0 (String.length se.ticket) ;
  let exts = assemble_extensions assemble_session_ticket_extension se.extensions in
  String.concat "" [ Bytes.unsafe_to_string buf ; se.nonce ; Bytes.unsafe_to_string ticketlen ; se.ticket ; exts ]

let assemble_client_dh_key_exchange kex =
  let len = String.length kex in
  let buf = Bytes.create (len + 2) in
  Bytes.set_uint16_be buf 0 len;
  Bytes.blit_string kex 0 buf 2 len;
  Bytes.unsafe_to_string buf

let assemble_client_ec_key_exchange kex =
  let len = String.length kex in
  let buf = Bytes.create (len + 1) in
  Bytes.set_uint8 buf 0 len;
  Bytes.blit_string kex 0 buf 1 len;
  Bytes.unsafe_to_string buf

let assemble_hello_retry_request hrr =
  let exts = `SelectedGroup hrr.selected_group :: hrr.extensions in
  let version, exts = match hrr.retry_version with
    | `TLS_1_3 -> `TLS_1_2, `SelectedVersion `TLS_1_3 :: exts
    | x -> x, exts
  in
  let v = assemble_protocol_version version in
  let sid = assemble_sid hrr.sessionid in
  let cs = assemble_ciphersuite (hrr.ciphersuite :> Ciphersuite.ciphersuite) in
  (* useless compression method *)
  let cm = String.make 1 '\x00' in
  let extensions = assemble_extensions ~none_if_empty:true assemble_retry_extension exts in
  String.concat "" [ v ; helloretryrequest ; sid ; cs ; cm ; extensions ]

let assemble_hs typ len =
  let buf = Bytes.create 4 in
  Bytes.set_uint8 buf 0 (handshake_type_to_int typ);
  set_uint24_len ~off:1 buf len;
  Bytes.unsafe_to_string buf

let assemble_message_hash len =
  assemble_hs MESSAGE_HASH len

let assemble_key_update req =
  String.make 1 (Char.unsafe_chr (key_update_request_type_to_int req))

let assemble_handshake hs =
  let (payload, payload_type) =
    match hs with
    | ClientHello ch -> (assemble_client_hello ch, CLIENT_HELLO)
    | ServerHello sh -> (assemble_server_hello sh, SERVER_HELLO)
    | HelloRetryRequest hr -> (assemble_hello_retry_request hr, SERVER_HELLO)
    | Certificate cs -> (cs, CERTIFICATE)
    | CertificateRequest cr -> (cr, CERTIFICATE_REQUEST)
    | CertificateVerify c -> (c, CERTIFICATE_VERIFY)
    | ServerKeyExchange kex -> (kex, SERVER_KEY_EXCHANGE)
    | ClientKeyExchange kex -> (kex, CLIENT_KEY_EXCHANGE)
    | ServerHelloDone -> ("", SERVER_HELLO_DONE)
    | HelloRequest -> ("", HELLO_REQUEST)
    | Finished fs -> (fs, FINISHED)
    | SessionTicket st -> (assemble_session_ticket st, SESSION_TICKET)
    | EncryptedExtensions ee ->
       let cs = assemble_extensions assemble_encrypted_extension ee in
       (cs, ENCRYPTED_EXTENSIONS)
    | KeyUpdate req ->
      let cs = assemble_key_update req in
      (cs, KEY_UPDATE)
    | EndOfEarlyData -> ("", END_OF_EARLY_DATA)
  in
  let pay_len = String.length payload in
  let buf = assemble_hs payload_type pay_len in
  buf ^ payload

let assemble_alert ?(level = Packet.FATAL) typ =
  let buf = Bytes.create 2 in
  Bytes.set_uint8 buf 1 (alert_type_to_int typ);
  Bytes.set_uint8 buf 0 (alert_level_to_int level) ;
  Bytes.unsafe_to_string buf

let assemble_change_cipher_spec =
  String.make 1 '\x01'
