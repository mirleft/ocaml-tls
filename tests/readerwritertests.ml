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
  [ "ReadWrite version" >:: readerwriter_version Core.TLS_1_0 ;
    "ReadWrite version" >:: readerwriter_version Core.TLS_1_1 ;
    "ReadWrite version" >:: readerwriter_version Core.TLS_1_2 ]

let readerwriter_tests =
  version_tests
