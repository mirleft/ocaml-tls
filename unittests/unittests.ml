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

let suite =
  "All" >::: [
    "Reader" >:::
      List.mapi
        (fun i f -> "Parse version " ^ string_of_int i >:: f)
        version_parser_tests
  ]

