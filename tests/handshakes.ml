open OUnit2
open Tls
open Testlib
open Nocrypto
open Core
open Asn_grammars
(*
let first_48_random =
  list_to_cstruct [
0x52; 0xfe; 0xe9; 0x8b; 0xfe; 0x55; 0x06; 0xde; 0xde; 0x95; 0x78; 0x23; 0xad; 0x47; 0x59; 0xe8; 0x33; 0xb6; 0xfc; 0x8b; 0x99; 0x99; 0x6f; 0x1e; 0x10; 0x07; 0x7c; 0xb9; 0x9f; 0x18; 0x32; 0x44; 0xec; 0x6b; 0x85; 0x12; 0xd9; 0xdb; 0x2e; 0x86; 0xa9; 0x9c; 0xd3; 0x4a; 0xa3; 0x11; 0x64; 0xad ]

let refresh_rng () =
  let f = Fortuna.create () in
  Fortuna.reseed ~g:f (Cstruct.of_string "\001\002\003\004") ;
  Rng.set_gen f

let test_rng _ =
  refresh_rng () ;
  assert_cs_eq (Rng.generate 48) first_48_random

let b64decode = o Base64.decode Cstruct.of_string

let cert =
  let raw = b64decode "MIICYzCCAcwCCQDLbE6ES1ih1DANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRUwEwYDVQQDDAxZT1VSIE5BTUUhISExGDAWBgkqhkiG9w0BCQEWCW1lQGJhci5kZTAeFw0xNDAyMTcyMjA4NDVaFw0xNTAyMTcyMjA4NDVaMHYxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFTATBgNVBAMMDFlPVVIgTkFNRSEhITEYMBYGCSqGSIb3DQEJARYJbWVAYmFyLmRlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2QEje5rwhlD2iq162+Ng3AH9BfA/jNJLDqi9VPk1eMUNGicJvK+aOANKIsOOr9v4RiEXZSYmFEvGSy+Sf1bCDHwHLLSdNs6Y49b77POgatrVZOTREBE/t1soVT3a/vVJWCLtVCjm70u0S5tcfn4S6IapeIYAVAmcaqwSa+GQNoQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAIo4ZppIlp3JRyltRC1/AyCC0tsh5TdM3W7258wdoP3lEe08UlLwpnPcaJ/cX8rMG4Xf4it77yrbVrU3MumBEGN5TW4jn4+iZyFbp6TT3OUF55nsXDjNHBbudeDVpGuPTI6CZQVhU5qEMF3xmlokG+VV+HCDTglNQc+fdLM0LoNF"
  in
  match Certificate.parse raw with
  | Some x -> x
  | None   -> raise (Invalid_argument "no certificate found")

let key =
  let raw = b64decode "MIICXQIBAAKBgQC2QEje5rwhlD2iq162+Ng3AH9BfA/jNJLDqi9VPk1eMUNGicJvK+aOANKIsOOr9v4RiEXZSYmFEvGSy+Sf1bCDHwHLLSdNs6Y49b77POgatrVZOTREBE/t1soVT3a/vVJWCLtVCjm70u0S5tcfn4S6IapeIYAVAmcaqwSa+GQNoQIDAQABAoGAd/CShG8g/JBMh9Nz/8KAuKHRHc2BvysIM1C62cSosgaFmdRrazJfBrEv3Nlc2/0uc2dVYIxuvm8bIFqi2TWOdX9jWJf6oXwEPXCD0SaDbJTaoh0b+wjyHuaGlttYZtvmf8mK1BOhyl3vNMxh/8Re0dGvGgPZHpn8zanaqfGVz+ECQQDngieUpwzxA0QZGZKRYhHoLEaPiQzBaXphqWcCLLN7oAKxZlUCUckxRRe0tKINf0cB3Kr9gGQjPpm0YoqXo8mNAkEAyYgdd+JDi9FH3Cz6ijvPU0hYkriwTii0V09+Ar5DvYQNzNEIEJu8Q3Yte/TPRuK8zhnp97Bsy9v/Ji/LSWbtZQJBAJe9y8u3otfmWCBLjrIUIcCYJLe4ENBFHp4ctxPJ0Ora+mjkthuLF+BfdSZQr1dBcX1a8giuuvQO+Bgv7r9t75ECQC7FomEyaA7JEW5uGe9/Fgz0G2ph5rkdBU3GKy6jzcDsJu/EC6UfH8Bgawn7tSd0c/E5Xm2Xyog9lKfeK8XrV2kCQQCTico5lQPjfIwjhvn45ALc/0OrkaK0hQNpXgUNFJFQtuX2WMD5flMyA5PCx5XBU8gEMHYa8Kr5d6uoixnbS0cZ"
  in
  match Asn_grammars.PK.rsa_private_of_cstruct raw with
  | Some pk -> pk
  | None -> raise (Invalid_argument "no private key")

let create_cstruct_0 n =
  let buf = Cstruct.create n in
  for i = 0 to pred n do
    Cstruct.set_uint8 buf i 0
  done ;
  buf

let client_packages : tls_handshake list =
  [ ClientHello { version = TLS_1_0 ;
                  random = create_cstruct_0 32 ;
                  sessionid = None ;
                  ciphersuites = Ciphersuite.([TLS_RSA_WITH_RC4_128_MD5 ; TLS_EMPTY_RENEGOTIATION_INFO_SCSV]) ;
                  extensions = [] }
]

let ms = list_to_cstruct [
             0xcb; 0xbc; 0x37; 0xb8; 0x0e; 0xb4; 0x77; 0x91; 0x28; 0xaf; 0x71; 0xdc; 0xe0; 0xa0; 0x68; 0xa3; 0x3c; 0xd5; 0x03; 0xa9; 0x31; 0xb0; 0x20; 0x3e; 0x68; 0x4b; 0x16; 0x8c; 0xd1; 0xba; 0x3a; 0x8d; 0x0a; 0xf5; 0x36; 0xdd; 0x85; 0xfc; 0xa6; 0x60; 0x41; 0x31; 0xe8; 0x23; 0x3e; 0x58; 0x3f; 0xb6
           ]

(* carefully crafted 0x00 0x02 77 * 0x01 0x00 <pms>,
   where pms is 0x03 0x01 46 * 0x00,
   encrypted with key from cert above *)
let ckex = list_to_cstruct [
0x8d; 0x2e; 0x9f; 0x49; 0x3e; 0xbb; 0x9e; 0xed; 0x5e; 0x92; 0xff; 0x23; 0x90; 0x42; 0x14; 0x9f;
0xde; 0x25; 0x4e; 0x60; 0xb1; 0x2c; 0x3c; 0x80; 0xa6; 0x51; 0xdf; 0x73; 0x69; 0x9a; 0x5c; 0x2f;
0x74; 0xc6; 0x1f; 0x80; 0xaa; 0x2b; 0xae; 0x33; 0xc5; 0xdc; 0x99; 0xcd; 0xee; 0xe0; 0xfa; 0xc1;
0xe9; 0x0e; 0xce; 0xf9; 0x1e; 0xab; 0x03; 0x97; 0x37; 0x1c; 0x4a; 0xa1; 0xc0; 0xbb; 0x84; 0x53;
0xf9; 0x5d; 0x17; 0x40; 0xd9; 0x1c; 0x50; 0xf8; 0x75; 0x77; 0x4b; 0x92; 0xad; 0x09; 0xd7; 0x6c;
0xc1; 0x4e; 0x80; 0x2a; 0xa7; 0x77; 0x36; 0x8b; 0x70; 0x5f; 0xab; 0xf9; 0x5c; 0x8f; 0x85; 0x8e;
0x5d; 0x96; 0xb0; 0x65; 0xc2; 0xbd; 0x92; 0x80; 0xbc; 0xcd; 0x4e; 0xae; 0xfd; 0xd6; 0xe8; 0x54;
0xef; 0x48; 0x74; 0xad; 0xd1; 0xfe; 0x3e; 0x8a; 0xb4; 0x64; 0xc4; 0xda; 0x7b; 0x59; 0x26; 0xc5
            ]

let server_test client_hs _ =
  refresh_rng () ;
  let ch : tls_handshake = List.hd client_hs in
  match ch with
  | ClientHello chdata ->
     let cipher = List.hd chdata.ciphersuites in
     let version = chdata.version in
     let ch_raw = Writer.assemble_handshake ch in
     let ch_pack = Writer.assemble_hdr version (Packet.HANDSHAKE, ch_raw) in
     let sst = Server.new_connection ~cert:(cert, key) () in
     (match Engine.handle_tls sst ch_pack with
      | `Ok (sst', out, None) ->
         let ssp = sst'.security_parameters in
         assert_equal ssp.ciphersuite cipher ;
         assert_cs_eq ssp.client_random chdata.random ;
         assert_cs_eq ssp.server_random (Cstruct.sub first_48_random 0 32) ;
         assert_equal ssp.dh_state `Initial ;
         assert_equal ssp.peer_certificate `Cert_unknown ;
         assert_equal ssp.protocol_version version ;
         (* expecting out: server hello ; certificate ; server hello done *)
         (match Flow.separate_records out with
          | Ok ([sh_raw ; sc_raw ; shd_raw], leftover) ->
             assert_equal (Cstruct.len leftover) 0 ;
             let hdr1, sh_raw' = sh_raw in
             assert_equal hdr1.content_type Packet.HANDSHAKE ;
             assert_equal hdr1.version TLS_1_0 ;
             let hdr2, sc_raw' = sc_raw in
             assert_equal hdr2.content_type Packet.HANDSHAKE ;
             assert_equal hdr2.version TLS_1_0 ;
             let hdr3, shd_raw' = shd_raw in
             assert_equal hdr3.content_type Packet.HANDSHAKE ;
             assert_equal hdr3.version TLS_1_0 ;
             Reader.(match
                 parse_handshake sh_raw',
                 parse_handshake sc_raw',
                 parse_handshake shd_raw'
                      with
                      | (Or_error.Ok (ServerHello sh), Or_error.Ok (Certificate sc), Or_error.Ok (ServerHelloDone)) ->
                         assert_equal sh.version TLS_1_0 ;
                         assert_cs_eq sh.random (Cstruct.sub first_48_random 0 32) ;
                         assert_equal sh.sessionid None ;
                         assert_equal sh.ciphersuites cipher ;
                         (* server hello must only include extensions which are sent in client hello *)
                         (* assert_equal sh.extensions [] *)
                         assert_equal (List.length sc) 1 ;
                         assert_cs_eq (List.hd sc) (Certificate.cs_of_cert cert) ;
                         (* send ckex, ccs, cfin *)
                         (match Certificate.(asn_of_cert cert).tbs_cert.pk_info with
                          | Asn_grammars.PK.RSA key ->
                             let kex_raw = Writer.assemble_handshake (ClientKeyExchange ckex) in
                             let kex_pack = Writer.assemble_hdr version (Packet.HANDSHAKE, kex_raw) in
                             (match Engine.handle_tls sst' kex_pack with
                              | `Ok (sst'', out, None) ->
                                 let ssp' = sst''.security_parameters in
                                 assert_equal (Cstruct.len out) 0 ;
                                 assert_equal ssp'.protocol_version TLS_1_0 ;
                                 assert_equal ssp'.ciphersuite cipher ;
                                 assert_equal ssp'.dh_state `Initial ;
                                 assert_cs_eq ssp'.client_random (create_cstruct_0 32) ;
                                 assert_cs_eq ssp'.server_random (Cstruct.sub first_48_random 0 32) ;
                                 assert_cs_eq ssp'.master_secret ms ;
                                 let ccs_raw = Writer.assemble_change_cipher_spec in
                                 let ccs_pack = Writer.assemble_hdr version (Packet.CHANGE_CIPHER_SPEC, ccs_raw) in
                                 (match Engine.handle_tls sst'' ccs_pack with
                                  | `Ok (sst''', out, None) ->
                                     (* this actually produces a change cipher spec - correct? *)
                                     (* produce a finished message, encrypt and send over *)
                                     ()
                                  | _ -> assert_failure "bad change cipher spec!")
                              | _ -> assert_failure "bad client kex")
                          | _ -> assert_failure "couldn't find public key of certificate")
                      | _ -> assert_failure "parsing server response failed")
          | _ -> assert_failure "separate records while answering client hello was not good")
      | _ -> assert_failure "client hello was not good")
  | _ -> assert_failure "bad handshake input data"
 *)
let handshake_tests =
 [
(*  "Rng" >:: test_rng ;
  "Rng_2" >:: test_rng ;
  "server_hs" >:: (server_test client_packages) *)
 ]
