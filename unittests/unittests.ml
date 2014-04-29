open OUnit2
open Cstruct
open Tls

let parse_version_0 _ =
  let ver = create 2 in
  set_uint8 ver 0 3;
  set_uint8 ver 1 1;
  match Reader.parse_version ver with
  | Reader.Or_error.Ok v    -> assert_equal v Core.TLS_1_0
  | Reader.Or_error.Error _ -> assert_failure "Version parser broken"

let suite =
  "All" >::: [
    "Reader" >::: [
      "Parse_version_int" >:: parse_version_0
    ]
  ]

