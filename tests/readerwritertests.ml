open OUnit2
open Tls
open Testlib

let readerwriter_version v _ =
  let buf = Writer.assemble_protocol_version v in
  Reader.(match parse_version buf with
          | Or_error.Ok ver ->
             assert_equal v ver ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_protocol_version v in
             (match parse_version buf' with
              | Or_error.Ok ver' -> assert_equal v ver'
              | Or_error.Error _ -> assert_failure "read and write version broken")
          | Or_error.Error _ -> assert_failure "read and write version broken")

let version_tests =
  [ "ReadWrite version TLS-1.0" >:: readerwriter_version Core.TLS_1_0 ;
    "ReadWrite version TLS-1.1" >:: readerwriter_version Core.TLS_1_1 ;
    "ReadWrite version TLS-1.2" >:: readerwriter_version Core.TLS_1_2 ]

let readerwriter_header (v, ct, cs) _ =
  let buf = Writer.assemble_hdr v (ct, cs) in
  match Reader.parse_hdr buf with
  | (Some ct', Some v', l) ->
     assert_equal v v' ;
     assert_equal ct ct' ;
     assert_equal (Cstruct.len cs) l ;
     let buf' = Writer.assemble_hdr v' (ct', cs) in
     (match Reader.parse_hdr buf' with
      | (Some ct'', Some v'', l') ->
         assert_equal v v'' ;
         assert_equal ct ct'' ;
         assert_equal (Cstruct.len cs) l' ;
      | _ -> assert_failure "inner header broken")
  | _ -> assert_failure "header broken"

let header_tests =
  let a = list_to_cstruct [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15 ] in
  [ "ReadWrite header" >:: readerwriter_header (Core.TLS_1_0, Packet.HANDSHAKE, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_1, Packet.HANDSHAKE, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_2, Packet.HANDSHAKE, a) ;

    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_0, Packet.APPLICATION_DATA, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_1, Packet.APPLICATION_DATA, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_2, Packet.APPLICATION_DATA, a) ;

    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_0, Packet.CHANGE_CIPHER_SPEC, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_1, Packet.CHANGE_CIPHER_SPEC, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_2, Packet.CHANGE_CIPHER_SPEC, a) ;

    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_0, Packet.HEARTBEAT, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_1, Packet.HEARTBEAT, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_2, Packet.HEARTBEAT, a) ;

    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_0, Packet.ALERT, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_1, Packet.ALERT, a) ;
    "ReadWrite header" >:: readerwriter_header (Core.TLS_1_2, Packet.ALERT, a) ;
 ]

let readerwriter_alert (lvl, typ) _ =
  let buf, expl = match lvl with
    | None -> (Writer.assemble_alert typ, Packet.FATAL)
    | Some l -> (Writer.assemble_alert ~level:l typ, l)
  in
  Reader.(match parse_alert buf with
          | Or_error.Ok (l', t') ->
             assert_equal expl l' ;
             assert_equal typ t' ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_alert ~level:l' t' in
             (match parse_alert buf' with
              | Or_error.Ok (l'', t'') -> assert_equal expl l'' ; assert_equal typ t''
              | Or_error.Error _ -> assert_failure "inner read and write alert broken")
          | Or_error.Error _ -> assert_failure "read and write alert broken")

let rw_alert_tests = Packet.([
  ( None,  CLOSE_NOTIFY ) ;
  ( None,  UNEXPECTED_MESSAGE ) ;
  ( None,  BAD_RECORD_MAC ) ;
  ( None,  DECRYPTION_FAILED ) ;
  ( None,  RECORD_OVERFLOW ) ;
  ( None,  DECOMPRESSION_FAILURE ) ;
  ( None,  HANDSHAKE_FAILURE ) ;
  ( None,  NO_CERTIFICATE_RESERVED ) ;
  ( None,  BAD_CERTIFICATE ) ;
  ( None,  UNSUPPORTED_CERTIFICATE ) ;
  ( None,  CERTIFICATE_REVOKED ) ;
  ( None,  CERTIFICATE_EXPIRED ) ;
  ( None,  CERTIFICATE_UNKNOWN ) ;
  ( None,  ILLEGAL_PARAMETER ) ;
  ( None,  UNKNOWN_CA ) ;
  ( None,  ACCESS_DENIED ) ;
  ( None,  DECODE_ERROR ) ;
  ( None,  DECRYPT_ERROR ) ;
  ( None,  EXPORT_RESTRICTION_RESERVED ) ;
  ( None,  PROTOCOL_VERSION ) ;
  ( None,  INSUFFICIENT_SECURITY ) ;
  ( None,  INTERNAL_ERROR ) ;
  ( None,  USER_CANCELED ) ;
  ( None,  NO_RENEGOTIATION ) ;
  ( None,  UNSUPPORTED_EXTENSION ) ;
  ( None,  CERTIFICATE_UNOBTAINABLE ) ;
  ( None,  UNRECOGNIZED_NAME ) ;
  ( None,  BAD_CERTIFICATE_STATUS_RESPONSE ) ;
  ( None,  BAD_CERTIFICATE_HASH_VALUE ) ;
  ( None,  UNKNOWN_PSK_IDENTITY ) ;

  ( Some FATAL,  CLOSE_NOTIFY ) ;
  ( Some FATAL,  UNEXPECTED_MESSAGE ) ;
  ( Some FATAL,  BAD_RECORD_MAC ) ;
  ( Some FATAL,  DECRYPTION_FAILED ) ;
  ( Some FATAL,  RECORD_OVERFLOW ) ;
  ( Some FATAL,  DECOMPRESSION_FAILURE ) ;
  ( Some FATAL,  HANDSHAKE_FAILURE ) ;
  ( Some FATAL,  NO_CERTIFICATE_RESERVED ) ;
  ( Some FATAL,  BAD_CERTIFICATE ) ;
  ( Some FATAL,  UNSUPPORTED_CERTIFICATE ) ;
  ( Some FATAL,  CERTIFICATE_REVOKED ) ;
  ( Some FATAL,  CERTIFICATE_EXPIRED ) ;
  ( Some FATAL,  CERTIFICATE_UNKNOWN ) ;
  ( Some FATAL,  ILLEGAL_PARAMETER ) ;
  ( Some FATAL,  UNKNOWN_CA ) ;
  ( Some FATAL,  ACCESS_DENIED ) ;
  ( Some FATAL,  DECODE_ERROR ) ;
  ( Some FATAL,  DECRYPT_ERROR ) ;
  ( Some FATAL,  EXPORT_RESTRICTION_RESERVED ) ;
  ( Some FATAL,  PROTOCOL_VERSION ) ;
  ( Some FATAL,  INSUFFICIENT_SECURITY ) ;
  ( Some FATAL,  INTERNAL_ERROR ) ;
  ( Some FATAL,  USER_CANCELED ) ;
  ( Some FATAL,  NO_RENEGOTIATION ) ;
  ( Some FATAL,  UNSUPPORTED_EXTENSION ) ;
  ( Some FATAL,  CERTIFICATE_UNOBTAINABLE ) ;
  ( Some FATAL,  UNRECOGNIZED_NAME ) ;
  ( Some FATAL,  BAD_CERTIFICATE_STATUS_RESPONSE ) ;
  ( Some FATAL,  BAD_CERTIFICATE_HASH_VALUE ) ;
  ( Some FATAL,  UNKNOWN_PSK_IDENTITY ) ;

  ( Some WARNING,  CLOSE_NOTIFY ) ;
  ( Some WARNING,  UNEXPECTED_MESSAGE ) ;
  ( Some WARNING,  BAD_RECORD_MAC ) ;
  ( Some WARNING,  DECRYPTION_FAILED ) ;
  ( Some WARNING,  RECORD_OVERFLOW ) ;
  ( Some WARNING,  DECOMPRESSION_FAILURE ) ;
  ( Some WARNING,  HANDSHAKE_FAILURE ) ;
  ( Some WARNING,  NO_CERTIFICATE_RESERVED ) ;
  ( Some WARNING,  BAD_CERTIFICATE ) ;
  ( Some WARNING,  UNSUPPORTED_CERTIFICATE ) ;
  ( Some WARNING,  CERTIFICATE_REVOKED ) ;
  ( Some WARNING,  CERTIFICATE_EXPIRED ) ;
  ( Some WARNING,  CERTIFICATE_UNKNOWN ) ;
  ( Some WARNING,  ILLEGAL_PARAMETER ) ;
  ( Some WARNING,  UNKNOWN_CA ) ;
  ( Some WARNING,  ACCESS_DENIED ) ;
  ( Some WARNING,  DECODE_ERROR ) ;
  ( Some WARNING,  DECRYPT_ERROR ) ;
  ( Some WARNING,  EXPORT_RESTRICTION_RESERVED ) ;
  ( Some WARNING,  PROTOCOL_VERSION ) ;
  ( Some WARNING,  INSUFFICIENT_SECURITY ) ;
  ( Some WARNING,  INTERNAL_ERROR ) ;
  ( Some WARNING,  USER_CANCELED ) ;
  ( Some WARNING,  NO_RENEGOTIATION ) ;
  ( Some WARNING,  UNSUPPORTED_EXTENSION ) ;
  ( Some WARNING,  CERTIFICATE_UNOBTAINABLE ) ;
  ( Some WARNING,  UNRECOGNIZED_NAME ) ;
  ( Some WARNING,  BAD_CERTIFICATE_STATUS_RESPONSE ) ;
  ( Some WARNING,  BAD_CERTIFICATE_HASH_VALUE ) ;
  ( Some WARNING,  UNKNOWN_PSK_IDENTITY ) ;
])

let rw_alert_tests =
  List.mapi
    (fun i f -> "RW alert " ^ string_of_int i >:: readerwriter_alert f)
    rw_alert_tests

let assert_dh_eq a b =
  Core.(assert_cs_eq a.dh_p b.dh_p) ;
  Core.(assert_cs_eq a.dh_g b.dh_g) ;
  Core.(assert_cs_eq a.dh_Ys b.dh_Ys)

let readerwriter_dh_params params _ =
  let buf = Writer.assemble_dh_parameters params in
  Reader.(match parse_dh_parameters buf with
          | Or_error.Ok (p, raw, rst) ->
             assert_equal (Cstruct.len rst) 0 ;
             assert_dh_eq p params ;
             assert_equal buf raw ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_dh_parameters p in
             (match parse_dh_parameters buf' with
              | Or_error.Ok (p', raw', rst') ->
                 assert_equal (Cstruct.len rst') 0 ;
                 assert_dh_eq p' params ;
                 assert_equal buf raw' ;
              | Or_error.Error _ -> assert_failure "inner read and write dh params broken")
          | Or_error.Error _ -> assert_failure "read and write dh params broken")

let rw_dh_params =
  let a = list_to_cstruct [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15 ] in
  let emp = list_to_cstruct [] in
  Core.([
         { dh_p = emp ; dh_g = emp ; dh_Ys = emp } ;
         { dh_p = a ; dh_g = emp ; dh_Ys = emp } ;
         { dh_p = emp ; dh_g = a ; dh_Ys = emp } ;
         { dh_p = emp ; dh_g = emp ; dh_Ys = a } ;
         { dh_p = a <+> a ; dh_g = a <+> a ; dh_Ys = a <+> a } ;
       ])

let rw_dh_tests =
  List.mapi
    (fun i f -> "RW dh_param " ^ string_of_int i >:: readerwriter_dh_params f)
    rw_dh_params

let readerwriter_digitally_signed params _ =
  let buf = Writer.assemble_digitally_signed params in
  Reader.(match parse_digitally_signed buf with
          | Or_error.Ok params' ->
             assert_cs_eq params params' ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_digitally_signed params' in
             (match parse_digitally_signed buf' with
              | Or_error.Ok params'' ->
                 assert_cs_eq params params''
              | Or_error.Error _ -> assert_failure "inner read and write digitally signed broken")
          | Or_error.Error _ -> assert_failure "read and write digitally signed broken")

let rw_ds_params =
  let a = list_to_cstruct [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15 ] in
  let emp = list_to_cstruct [] in
  [ a ; a <+> a ; emp ; emp <+> a ]

let rw_ds_tests =
  List.mapi
    (fun i f -> "RW digitally signed " ^ string_of_int i >:: readerwriter_digitally_signed f)
    rw_ds_params

let readerwriter_digitally_signed_1_2 (h, s, params) _ =
  let buf = Writer.assemble_digitally_signed_1_2 h s params in
  Reader.(match parse_digitally_signed_1_2 buf with
          | Or_error.Ok (h', s', params') ->
             assert_equal h h' ;
             assert_equal s s' ;
             assert_cs_eq params params' ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_digitally_signed_1_2 h' s' params' in
             (match parse_digitally_signed_1_2 buf' with
              | Or_error.Ok (h'', s'', params'') ->
                 assert_equal h h'' ;
                 assert_equal s s'' ;
                 assert_cs_eq params params''
              | Or_error.Error _ -> assert_failure "inner read and write digitally signed 1.2 broken")
          | Or_error.Error _ -> assert_failure "read and write digitally signed 1.2 broken")

let rec cartesian_product f a b =
  match b with
  | []    -> []
  | e::rt -> (List.map (fun x -> f x e) a) @ (cartesian_product f a rt)

let rw_ds_1_2_params =
  let a = list_to_cstruct [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15 ] in
  let emp = list_to_cstruct [] in
  let cs = [ a ; a <+> a ; emp ; emp <+> a ] in
  let hashes = Ciphersuite.([ NULL ; MD5 ; SHA ; SHA224 ; SHA256 ; SHA384 ; SHA512 ]) in
  let sign = Packet.([ ANONYMOUS ; RSA ; DSA ; ECDSA ]) in
  let h_s = cartesian_product (fun h s -> (h, s)) hashes sign in
  cartesian_product (fun (h, s) c -> (h, s, c)) h_s cs

let rw_ds_1_2_tests =
  List.mapi
    (fun i f -> "RW digitally signed 1.2 " ^ string_of_int i >:: readerwriter_digitally_signed_1_2 f)
    rw_ds_1_2_params

let rw_handshake_no_data hs _ =
  let buf = Writer.assemble_handshake hs in
  Reader.(match parse_handshake buf with
          | Or_error.Ok (hs', _, rest) ->
             assert_equal hs hs' ;
             assert_equal (Cstruct.len rest) 0;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_handshake hs' in
             (match parse_handshake buf' with
              | Or_error.Ok (hs'', _, rest) -> assert_equal hs hs'' ; assert_equal (Cstruct.len rest) 0
              | Or_error.Error _ -> assert_failure "handshake no data inner failed")
          | Or_error.Error _ -> assert_failure "handshake no data failed")

let rw_handshakes_no_data_vals = [ Core.HelloRequest ; Core.ServerHelloDone ]

let rw_handshake_no_data_tests =
  List.mapi
    (fun i f -> "handshake no data " ^ string_of_int i >:: rw_handshake_no_data f)
    rw_handshakes_no_data_vals

let rw_handshake_cstruct_data hs _ =
  let buf = Writer.assemble_handshake hs in
  Reader.(match parse_handshake buf with
          | Or_error.Ok (hs', _, rest) ->
             Readertests.cmp_handshake_cstruct hs hs' ;
             assert_equal (Cstruct.len rest) 0 ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_handshake hs' in
             (match parse_handshake buf' with
              | Or_error.Ok (hs'', _, rest) -> Readertests.cmp_handshake_cstruct hs hs' ; assert_equal (Cstruct.len rest) 0
              | Or_error.Error _ -> assert_failure "handshake cstruct data inner failed")
          | Or_error.Error _ -> assert_failure "handshake cstruct data failed")

let rw_handshake_cstruct_data_vals =
  let data_cs = list_to_cstruct [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11 ] in
  let emp = list_to_cstruct [ ] in
  Core.([ ServerKeyExchange emp ;
          ServerKeyExchange data_cs ;
          Finished emp ;
          Finished data_cs ;
          ClientKeyExchange emp ;
          ClientKeyExchange data_cs ;
          Certificate [] ;
          Certificate [data_cs] ;
          Certificate [data_cs; data_cs] ;
          Certificate [data_cs ; emp] ;
          Certificate [emp ; data_cs] ;
          Certificate [emp ; data_cs ; emp] ;
          Certificate [emp ; data_cs ; emp ; data_cs]
       ])

let rw_handshake_cstruct_data_tests =
  List.mapi
    (fun i f -> "handshake cstruct data " ^ string_of_int i >:: rw_handshake_cstruct_data f)
    rw_handshake_cstruct_data_vals

let rw_handshake_client_hello hs _ =
  let buf = Writer.assemble_handshake hs in
  Reader.(match parse_handshake buf with
          | Or_error.Ok (hs', _, rest) ->
             Core.(match hs, hs' with
                   | ClientHello ch, ClientHello ch' ->
                      Readertests.cmp_client_hellos ch ch' ;
                   | _ -> assert_failure "handshake client hello broken") ;
             assert_equal (Cstruct.len rest) 0 ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_handshake hs' in
             (match parse_handshake buf' with
              | Or_error.Ok (hs'', _, rest) ->
                 assert_equal (Cstruct.len rest) 0 ;
                 Core.(match hs, hs'' with
                       | ClientHello ch, ClientHello ch'' ->
                          Readertests.cmp_client_hellos ch ch'' ;
                       | _ -> assert_failure "handshake client hello broken")
              | Or_error.Error _ -> assert_failure "handshake client hello inner failed")
          | Or_error.Error _ -> assert_failure "handshake client hello failed")

let rw_handshake_client_hello_vals =
  let rnd = [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15 ] in
  let random = list_to_cstruct (rnd @ rnd) in
  Core.(let ch : client_hello =
          { version = TLS_1_2 ;
            random ;
            sessionid = None ;
            ciphersuites = [] ;
            extensions = []}
        in
        [
          ClientHello ch ;
          ClientHello { ch with version = TLS_1_0 } ;
          ClientHello { ch with version = TLS_1_1 } ;

          ClientHello { ch with ciphersuites = [ Ciphersuite.TLS_NULL_WITH_NULL_NULL ] } ;
          ClientHello { ch with ciphersuites = Ciphersuite.([ TLS_NULL_WITH_NULL_NULL ; TLS_RSA_WITH_NULL_MD5 ; TLS_RSA_WITH_AES_256_CBC_SHA ]) } ;

          ClientHello { ch with sessionid = (Some (list_to_cstruct rnd)) } ;
          ClientHello { ch with sessionid = (Some random) } ;

          ClientHello { ch with
                        ciphersuites = Ciphersuite.([ TLS_NULL_WITH_NULL_NULL ; TLS_RSA_WITH_NULL_MD5 ; TLS_RSA_WITH_AES_256_CBC_SHA ]) ;
                        sessionid = (Some random) } ;

          ClientHello { ch with extensions = [ Hostname None ] } ;
          ClientHello { ch with extensions = [ Hostname None ; Hostname None ] } ;
          ClientHello { ch with extensions = [ Hostname (Some "foobar") ] } ;
          ClientHello { ch with extensions = [ Hostname (Some "foobarblubb") ] } ;

          ClientHello { ch with extensions = [ Hostname (Some "foobarblubb") ; EllipticCurves Packet.([SECP521R1; SECP384R1]) ] } ;

          ClientHello { ch with extensions = [
                             Hostname (Some "foobarblubb") ;
                             EllipticCurves Packet.([SECP521R1; SECP384R1]) ;
                             ECPointFormats Packet.([UNCOMPRESSED ; ANSIX962_COMPRESSED_PRIME ;   ANSIX962_COMPRESSED_CHAR2 ]) ;
                             SignatureAlgorithms [(Ciphersuite.NULL, Packet.ANONYMOUS); (Ciphersuite.MD5, Packet.RSA)]
                           ] } ;

          ClientHello { ch with
                        ciphersuites = Ciphersuite.([ TLS_NULL_WITH_NULL_NULL ; TLS_RSA_WITH_NULL_MD5 ; TLS_RSA_WITH_AES_256_CBC_SHA ]) ;
                        sessionid = (Some random) ;
                        extensions = [ Hostname (Some "foobarblubb") ] } ;

          ClientHello { ch with
                        ciphersuites = Ciphersuite.([ TLS_NULL_WITH_NULL_NULL ; TLS_RSA_WITH_NULL_MD5 ; TLS_RSA_WITH_AES_256_CBC_SHA ]) ;
                        sessionid = (Some random) ;
                        extensions = [
                             Hostname (Some "foobarblubb") ;
                             EllipticCurves Packet.([SECP521R1; SECP384R1]) ;
                             ECPointFormats Packet.([UNCOMPRESSED ; ANSIX962_COMPRESSED_PRIME ;   ANSIX962_COMPRESSED_CHAR2 ]) ;
                             SignatureAlgorithms [(Ciphersuite.NULL, Packet.ANONYMOUS); (Ciphersuite.MD5, Packet.RSA)]
                      ] } ;

          ClientHello { ch with
                        ciphersuites = Ciphersuite.([ TLS_NULL_WITH_NULL_NULL ; TLS_RSA_WITH_NULL_MD5 ; TLS_RSA_WITH_AES_256_CBC_SHA ]) ;
                        sessionid = (Some random) ;
                        extensions = [
                             Hostname (Some "foobarblubb") ;
                             EllipticCurves Packet.([SECP521R1; SECP384R1]) ;
                             ECPointFormats Packet.([UNCOMPRESSED ; ANSIX962_COMPRESSED_PRIME ;   ANSIX962_COMPRESSED_CHAR2 ]) ;
                             SignatureAlgorithms [(Ciphersuite.NULL, Packet.ANONYMOUS); (Ciphersuite.MD5, Packet.RSA)] ;
                             SecureRenegotiation random
                      ] } ;

        ])

let rw_handshake_client_hello_tests =
  List.mapi
    (fun i f -> "handshake client hello " ^ string_of_int i >:: rw_handshake_client_hello f)
    rw_handshake_client_hello_vals

let rw_handshake_server_hello hs _ =
  let buf = Writer.assemble_handshake hs in
  Reader.(match parse_handshake buf with
          | Or_error.Ok (hs', _, rest) ->
             assert_equal (Cstruct.len rest) 0 ;
             Core.(match hs, hs' with
                   | ServerHello sh, ServerHello sh' ->
                      Readertests.cmp_server_hellos sh sh' ;
                   | _ -> assert_failure "handshake server hello broken") ;
             (* lets get crazy and do it one more time *)
             let buf' = Writer.assemble_handshake hs' in
             (match parse_handshake buf' with
              | Or_error.Ok (hs'', _, rest) ->
                 assert_equal (Cstruct.len rest) 0 ;
                 Core.(match hs, hs'' with
                       | ServerHello sh, ServerHello sh'' ->
                          Readertests.cmp_server_hellos sh sh'' ;
                       | _ -> assert_failure "handshake server hello broken")
              | Or_error.Error _ -> assert_failure "handshake server hello inner failed")
          | Or_error.Error _ -> assert_failure "handshake server hello failed")

let rw_handshake_server_hello_vals =
  let rnd = [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15 ] in
  let random = list_to_cstruct (rnd @ rnd) in
  Core.(let sh : server_hello =
          { version = TLS_1_2 ;
            random ;
            sessionid = None ;
            ciphersuites = Ciphersuite.TLS_NULL_WITH_NULL_NULL ;
            extensions = []}
        in
        [
          ServerHello sh ;
          ServerHello { sh with version = TLS_1_0 } ;
          ServerHello { sh with version = TLS_1_1 } ;

          ServerHello { sh with sessionid = (Some random) } ;

          ServerHello { sh with
                        sessionid = (Some random) ;
                        extensions = [Hostname None]
                      } ;

          ServerHello { sh with
                        sessionid = (Some random) ;
                        extensions = [Hostname None ; SecureRenegotiation random]
                      } ;

        ])

let rw_handshake_server_hello_tests =
  List.mapi
    (fun i f -> "handshake server hello " ^ string_of_int i >:: rw_handshake_server_hello f)
    rw_handshake_server_hello_vals

let readerwriter_tests =
  version_tests @
  header_tests @
  rw_alert_tests @
  rw_dh_tests @
  rw_ds_tests @
  rw_ds_1_2_tests @
  rw_handshake_no_data_tests @
  rw_handshake_cstruct_data_tests @
  rw_handshake_client_hello_tests @
  rw_handshake_server_hello_tests
