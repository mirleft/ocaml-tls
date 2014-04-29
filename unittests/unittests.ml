open OUnit2
open Cstruct
open Tls

let parse_version_0 _ =
  let ver = create 2 in
  set_uint8 ver 0 3;
  set_uint8 ver 1 0;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v Core.SSL_3
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let parse_version_1 _ =
  let ver = create 2 in
  set_uint8 ver 0 3;
  set_uint8 ver 1 1;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v Core.TLS_1_0
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let parse_version_2 _ =
  let ver = create 2 in
  set_uint8 ver 0 3;
  set_uint8 ver 1 2;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v Core.TLS_1_1
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let parse_version_3 _ =
  let ver = create 2 in
  set_uint8 ver 0 3;
  set_uint8 ver 1 3;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v Core.TLS_1_2
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let parse_version_4 _ =
  let ver = create 2 in
  set_uint8 ver 0 3;
  set_uint8 ver 1 4;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v Core.TLS_1_X
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let parse_version_5 _ =
  let ver = create 1 in
  set_uint8 ver 0 3;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_failure "Version parser broken"
  | Reader.Or_error.Error _ -> assert_bool "length too short" true

let parse_version_6 _ =
  let ver = create 2 in
  set_uint8 ver 0 2;
  set_uint8 ver 1 4;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_failure "Version parser broken"
  | Reader.Or_error.Error _ -> assert_bool "unknown version" true

let parse_version_7 _ =
  let ver = create 2 in
  set_uint8 ver 0 3;
  set_uint8 ver 1 42;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v TLS_1_X
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let parse_version_8 _ =
  let ver = create 2 in
  set_uint8 ver 0 4;
  set_uint8 ver 1 4;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_failure "Version parser broken"
  | Reader.Or_error.Error _ -> assert_bool "unknown version" true

let version_parser_tests = [ parse_version_0 ;
                             parse_version_1 ;
                             parse_version_2 ;
                             parse_version_3 ;
                             parse_version_4 ;
                             parse_version_5 ;
                             parse_version_6 ;
                             parse_version_7 ;
                             parse_version_8 ]

let suite =
  "All" >::: [
    "Reader" >:::
      List.mapi
        (fun i f -> "Parse version " ^ string_of_int i >:: f)
        version_parser_tests
  ]

