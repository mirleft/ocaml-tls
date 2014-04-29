open OUnit2
open Tls


let cs_appends = function
  | []   -> Cstruct.create 0
  | [cs] -> cs
  | csn  ->
      let cs = Cstruct.(create @@ lenv csn) in
      let _ =
        List.fold_left
          (fun off e ->
            let len = Cstruct.len e in
            ( Cstruct.blit e 0 cs off len ; off + len ))
          0 csn in
      cs

let (<>) cs1 cs2 = cs_appends [ cs1; cs2 ]

let list_to_cstruct xs =
  let open Cstruct in
  let l = List.length xs in
  let buf = create l in
  for i = 0 to pred l do
    set_uint8 buf i (List.nth xs i)
  done;
  buf

let uint16_to_cstruct i =
  let open Cstruct in
  let buf = create 2 in
  BE.set_uint16 buf 0 i;
  buf

let good_version_parser major minor result _ =
  let ver = list_to_cstruct [ major ; minor ] in
  Reader.(match parse_version ver with
          | Or_error.Ok v    -> assert_equal v result
          | Or_error.Error _ -> assert_failure "Version parser broken")

let bad_version_parser major minor _ =
  let ver = list_to_cstruct [ major ; minor ] in
  Reader.(match parse_version ver with
          | Or_error.Ok v    -> assert_failure "Version parser broken"
          | Or_error.Error _ -> assert_bool "unknown version" true)

let parse_version_too_short _ =
  let ver = list_to_cstruct [ 0 ] in
  Reader.(match parse_version ver with
          | Or_error.Ok v    -> assert_failure "Version parser broken"
          | Or_error.Error _ -> assert_bool "length too short" true)

let version_parser_tests = [
  good_version_parser 3 0 Core.SSL_3 ;
  good_version_parser 3 1 Core.TLS_1_0 ;
  good_version_parser 3 2 Core.TLS_1_1 ;
  good_version_parser 3 3 Core.TLS_1_2 ;
  good_version_parser 3 4 Core.TLS_1_X ;
  good_version_parser 3 42 Core.TLS_1_X ;

  bad_version_parser 2 4 ;
  bad_version_parser 4 4 ;
  bad_version_parser 0 2 ;

  parse_version_too_short
]

let version_tests =
  List.mapi
    (fun i f -> "Parse version " ^ string_of_int i >:: f)
    version_parser_tests

let good_header_parser (ct, (major, minor), l, (resct, resv)) _ =
  let buf =
    let pre = list_to_cstruct [ ct ; major ; minor ] in
    pre <> uint16_to_cstruct l
  in
  match Reader.parse_hdr buf with
  | (Some c, Some v, l') -> assert_equal c resct ;
                            assert_equal v resv ;
                            assert_equal l' l
  | _                    -> assert_failure "header parser broken"

let good_headers = [
  ( 20 , (3, 1), 100,  ( Packet.CHANGE_CIPHER_SPEC , Core.TLS_1_0) ) ;
  ( 21 , (3, 2), 10,   ( Packet.ALERT , Core.TLS_1_1) ) ;
  ( 22 , (3, 3), 1000, ( Packet.HANDSHAKE , Core.TLS_1_2) ) ;
  ( 23 , (3, 0), 1,    ( Packet.APPLICATION_DATA , Core.SSL_3) ) ;
  ( 24 , (3, 4), 20,   ( Packet.HEARTBEAT , Core.TLS_1_X) ) ;
]

let good_headers_tests =
  List.mapi
    (fun i args -> "Good header " ^ string_of_int i >:: good_header_parser args)
    good_headers

let bad_header_parser (ct, (major, minor), l) _ =
  let buf =
    let pre = list_to_cstruct [ ct ; major ; minor ] in
    pre <> uint16_to_cstruct l
  in
  match Reader.parse_hdr buf with
  | (Some c, Some v, l') -> assert_failure "header parser broken"
  | _                    -> assert_bool "header parser good" true

let bad_headers = [
  ( 19 , (3, 1), 100 ) ;
  ( 20 , (5, 1), 100 ) ;
  ( 16 , (3, 1), 100 ) ;
  ( 30 , (3, 1), 100 ) ;
  ( 20 , (0, 1), 100 ) ;
  ( 25 , (3, 3), 100 ) ;
]

let bad_headers_tests =
  List.mapi
    (fun i args -> "Bad header " ^ string_of_int i >:: bad_header_parser args)
    bad_headers

let good_alert_parser (lvl, typ, expected) _ =
  let buf = list_to_cstruct [ lvl ; typ ] in
  Reader.(match parse_alert buf with
          | Or_error.Ok al   -> assert_equal al expected
          | Or_error.Error _ -> assert_failure "alert parser broken")

let good_alerts =
  let w = Packet.WARNING in
  let f = Packet.FATAL in
  [
    (1, 0, (w, Packet.CLOSE_NOTIFY));
    (2, 0, (f, Packet.CLOSE_NOTIFY));
    (1, 10, (w, Packet.UNEXPECTED_MESSAGE));
    (2, 10, (f, Packet.UNEXPECTED_MESSAGE));
    (1, 20, (w, Packet.BAD_RECORD_MAC));
    (2, 20, (f, Packet.BAD_RECORD_MAC));
    (1, 21, (w, Packet.DECRYPTION_FAILED));
    (2, 21, (f, Packet.DECRYPTION_FAILED));
    (1, 22, (w, Packet.RECORD_OVERFLOW));
    (2, 22, (f, Packet.RECORD_OVERFLOW));
    (1, 30, (w, Packet.DECOMPRESSION_FAILURE));
    (2, 30, (f, Packet.DECOMPRESSION_FAILURE));
    (1, 40, (w, Packet.HANDSHAKE_FAILURE));
    (2, 40, (f, Packet.HANDSHAKE_FAILURE));
    (1, 41, (w, Packet.NO_CERTIFICATE_RESERVED));
    (2, 41, (f, Packet.NO_CERTIFICATE_RESERVED));
    (1, 42, (w, Packet.BAD_CERTIFICATE));
    (2, 42, (f, Packet.BAD_CERTIFICATE));
    (1, 43, (w, Packet.UNSUPPORTED_CERTIFICATE));
    (2, 43, (f, Packet.UNSUPPORTED_CERTIFICATE));
    (1, 44, (w, Packet.CERTIFICATE_REVOKED));
    (2, 44, (f, Packet.CERTIFICATE_REVOKED));
    (1, 45, (w, Packet.CERTIFICATE_EXPIRED));
    (2, 45, (f, Packet.CERTIFICATE_EXPIRED));
    (1, 46, (w, Packet.CERTIFICATE_UNKNOWN));
    (2, 46, (f, Packet.CERTIFICATE_UNKNOWN));
    (1, 47, (w, Packet.ILLEGAL_PARAMETER));
    (2, 47, (f, Packet.ILLEGAL_PARAMETER));
    (1, 48, (w, Packet.UNKNOWN_CA));
    (2, 48, (f, Packet.UNKNOWN_CA));
    (1, 49, (w, Packet.ACCESS_DENIED));
    (2, 49, (f, Packet.ACCESS_DENIED));
    (1, 50, (w, Packet.DECODE_ERROR));
    (2, 50, (f, Packet.DECODE_ERROR));
    (1, 51, (w, Packet.DECRYPT_ERROR));
    (2, 51, (f, Packet.DECRYPT_ERROR));
    (1, 60, (w, Packet.EXPORT_RESTRICTION_RESERVED));
    (2, 60, (f, Packet.EXPORT_RESTRICTION_RESERVED));
    (1, 70, (w, Packet.PROTOCOL_VERSION));
    (2, 70, (f, Packet.PROTOCOL_VERSION));
    (1, 71, (w, Packet.INSUFFICIENT_SECURITY));
    (2, 71, (f, Packet.INSUFFICIENT_SECURITY));
    (1, 80, (w, Packet.INTERNAL_ERROR));
    (2, 80, (f, Packet.INTERNAL_ERROR));
    (1, 90, (w, Packet.USER_CANCELED));
    (2, 90, (f, Packet.USER_CANCELED));
    (1, 100, (w, Packet.NO_RENEGOTIATION));
    (2, 100, (f, Packet.NO_RENEGOTIATION));
    (1, 110, (w, Packet.UNSUPPORTED_EXTENSION));
    (2, 110, (f, Packet.UNSUPPORTED_EXTENSION));
    (1, 111, (w, Packet.CERTIFICATE_UNOBTAINABLE));
    (2, 111, (f, Packet.CERTIFICATE_UNOBTAINABLE));
    (1, 112, (w, Packet.UNRECOGNIZED_NAME));
    (2, 112, (f, Packet.UNRECOGNIZED_NAME));
    (1, 113, (w, Packet.BAD_CERTIFICATE_STATUS_RESPONSE));
    (2, 113, (f, Packet.BAD_CERTIFICATE_STATUS_RESPONSE));
    (1, 114, (w, Packet.BAD_CERTIFICATE_HASH_VALUE));
    (2, 114, (f, Packet.BAD_CERTIFICATE_HASH_VALUE));
    (1, 115, (w, Packet.UNKNOWN_PSK_IDENTITY));
    (2, 115, (f, Packet.UNKNOWN_PSK_IDENTITY));
  ]

let good_alert_tests =
  List.mapi
    (fun i args -> "Good alert " ^ string_of_int i >:: good_alert_parser args)
    good_alerts

let bad_alert_parser (lvl, typ) _ =
  let buf = list_to_cstruct [ lvl ; typ ] in
  Reader.(match parse_alert buf with
          | Or_error.Ok _    -> assert_failure "bad alert passes"
          | Or_error.Error _ -> assert_bool "bad alert fails" true)

let bad_alerts = [ (3, 0); (1, 1); (2, 200); (0, 200) ]

let alert_too_small _ =
  let buf = list_to_cstruct [ 0 ] in
  Reader.(match parse_alert buf with
          | Or_error.Ok _    -> assert_failure "short alert passes"
          | Or_error.Error _ -> assert_bool "short alert fails" true)

let alert_too_small2 _ =
  let buf = list_to_cstruct [ 25 ] in
  Reader.(match parse_alert buf with
          | Or_error.Ok _    -> assert_failure "short alert passes"
          | Or_error.Error _ -> assert_bool "short alert fails" true)

let bad_alerts_tests =
  ("short alert" >:: alert_too_small) ::
  ("short alert 2" >:: alert_too_small2) ::
  (List.mapi
     (fun i args -> "Bad alert " ^ string_of_int i >:: bad_alert_parser args)
     bad_alerts)

let suite =
  "All" >::: [
    "Reader" >:::
      version_tests @
      good_headers_tests @ bad_headers_tests @
      good_alert_tests @ bad_alerts_tests
  ]

