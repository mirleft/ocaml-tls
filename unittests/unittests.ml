open OUnit2
open Tls

let good_version_parser major minor result _ =
  let open Cstruct in
  let ver = create 2 in
  set_uint8 ver 0 major;
  set_uint8 ver 1 minor;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v result
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let bad_version_parser major minor _ =
  let open Cstruct in
  let ver = create 2 in
  set_uint8 ver 0 major;
  set_uint8 ver 1 minor;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_failure "Version parser broken"
  | Reader.Or_error.Error _ -> assert_bool "unknown version" true

let parse_version_too_short _ =
  let open Cstruct in
  let ver = create 1 in
  set_uint8 ver 0 3;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_failure "Version parser broken"
  | Reader.Or_error.Error _ -> assert_bool "length too short" true

let version_parser_tests = [ good_version_parser 3 0 Core.SSL_3 ;
                             good_version_parser 3 1 Core.TLS_1_0 ;
                             good_version_parser 3 2 Core.TLS_1_1 ;
                             good_version_parser 3 3 Core.TLS_1_2 ;
                             good_version_parser 3 4 Core.TLS_1_X ;
                             good_version_parser 3 42 Core.TLS_1_X ;

                             bad_version_parser 2 4 ;
                             bad_version_parser 4 4 ;
                             bad_version_parser 0 2 ;

                             parse_version_too_short ]

let version_tests =
  List.mapi
    (fun i f -> "Parse version " ^ string_of_int i >:: f)
    version_parser_tests

let good_header_parser (ct, (major, minor), l, (resct, resv)) _ =
  let open Cstruct in
  let buf = create 5 in
  set_uint8 buf 0 ct;
  set_uint8 buf 1 major;
  set_uint8 buf 2 minor;
  BE.set_uint16 buf 3 l;
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
  let open Cstruct in
  let buf = create 5 in
  set_uint8 buf 0 ct;
  set_uint8 buf 1 major;
  set_uint8 buf 2 minor;
  BE.set_uint16 buf 3 l;
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

let suite =
  "All" >::: [
    "Reader" >:::
      version_tests @ good_headers_tests @ bad_headers_tests
  ]

