open OUnit2

open Testlib

open Tls
open Tls.X509

open Tls.Certificate

let load file =
  cs_mmap ("./tests/testcertificates/" ^ file ^ ".pem")

let priv =
  PK.of_pem_cstruct1 (load "private/cakey")

let cert name =
  Cert.of_pem_cstruct1 (load name)

let invalid_cas = [
  "cacert-basicconstraint-ca-false";
  "cacert-unknown-critical-extension" ;
  "cacert-keyusage-crlsign" ;
  "cacert-ext-usage-timestamping"
]

let test_invalid_ca name _ =
  let c = cert name in
  let pub = Nocrypto.RSA.pub_of_priv priv in
  let open Asn_grammars in
  ( match Certificate.(asn_of_cert c).tbs_cert.pk_info with
    | PK.RSA pub' when pub = pub' -> ()
    | _                           -> assert_failure "public / private key doesn't match" ) ;
  assert_equal (List.length (valid_cas ~time:0 [c])) 0

let invalid_ca_tests =
  List.mapi
    (fun i args -> "invalid CA " ^ string_of_int i >:: test_invalid_ca args)
    invalid_cas

let cacert = cert "cacert"
let cacert_pathlen0 = cert "cacert-pathlen-0"
let cacert_ext = cert "cacert-unknown-extension"
let cacert_ext_ku = cert "cacert-ext-usage"
let cacert_v1 = cert "cacert-v1"

let test_valid_ca c _ =
  let pub = Nocrypto.RSA.pub_of_priv priv in
  let open Asn_grammars in
  ( match (asn_of_cert c).tbs_cert.pk_info with
    | PK.RSA pub' when pub = pub' -> ()
    | _                           -> assert_failure "public / private key doesn't match" ) ;
  assert_equal (List.length (valid_cas ~time:0 [c])) 1

let valid_ca_tests = [
  "valid CA cacert" >:: test_valid_ca cacert ;
  "valid CA cacert_pathlen0" >:: test_valid_ca cacert_pathlen0 ;
  "valid CA cacert_ext" >:: test_valid_ca cacert_ext ;
  "valid CA cacert_v1" >:: test_valid_ca cacert_v1
]

let first_cert name =
  Cert.of_pem_cstruct1 (load ("first/" ^ name))

(* ok, now some real certificates *)
let first_certs = [
  ( "first", true,
    [ "bar.foobar.com" ; "foo.foobar.com" ; "foobar.com" ],
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ( "first-basicconstraint-true" , false, [ "ca.foobar.com" ],
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ( "first-keyusage-and-timestamping", true, [ "ext.foobar.com" ],
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], Some [`TimeStamping] ) ;
  ( "first-keyusage-any", true, [ "any.foobar.com" ],
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], Some [`TimeStamping; `Any] ) ;
  ( "first-keyusage-nonrep", true, [ "key.foobar.com" ],
    [ `ContentCommitment ], None ) ;
  ( "first-unknown-critical-extension", false,
    [ "blafasel.com" ; "foo.foobar.com" ; "foobar.com" ],
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ( "first-unknown-extension", true, [ "foobar.com" ],
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
]

let test_valid_ca_cert server chain valid name ca _ =
  match valid, verify_chain_of_trust ~time:0 ~host:name ~anchors:ca (server, chain) with
  | false, `Ok     -> assert_failure "expected to fail, but didn't"
  | false, `Fail _ -> ()
  | true , `Ok     -> ()
  | true , `Fail c -> assert_failure ("valid certificate " ^ certificate_failure_to_string c)

let strict_test_valid_ca_cert server chain valid name ca =
  test_valid_ca_cert server chain valid (`Strict name) ca

let wildcard_test_valid_ca_cert server chain valid name ca =
  test_valid_ca_cert server chain valid (`Wildcard name) ca

let test_cert c usages extusage _ =
  ( match cert_usage c with
    | None    -> assert_failure "key usage is different"
    | Some xs -> List.iter (fun u -> assert_bool "usage is different" (List.mem u xs)) usages ) ;
  ( match cert_extended_usage c, extusage with
    | None   , None    -> ()
    | Some xs, Some yy -> List.iter (fun eu -> assert_bool "ext_usage is bad" (List.mem eu xs)) yy
    | _     , _        -> assert_failure "extended key usage broken" )

let first_cert_tests =
  List.mapi
    (fun i (name, _, _, us, eus) ->
     "certificate property testing " ^ string_of_int i >:: test_cert (first_cert name) us eus)
    first_certs

let first_cert_ca_test (ca, x) =
  List.flatten
    (List.map
       (fun (name, valid, cns, _, _) ->
        let c = first_cert name in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: strict_test_valid_ca_cert c [] valid cn [ca])
                  cns @
        List.mapi (fun i cn ->
                   "certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c [] valid cn [ca])
                  cns
       )
    first_certs)

let ca_tests f =
  List.flatten (List.map f
                         [ (cacert, "cacert") ;
                           (cacert_pathlen0, "cacert_pathlen0") ;
                           (cacert_ext, "cacert_ext") ;
                           (cacert_ext_ku, "cacert_ext_ku") ;
                           (cacert_v1, "cacert_v1") ])

let first_wildcard_certs = [
  ( "first-wildcard-subjaltname",
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ( "first-wildcard",
    [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
]

let first_wildcard_cert_tests =
  List.mapi
    (fun i (name, us, eus) ->
     "wildcard certificate property testing " ^ string_of_int i >:: test_cert (first_cert name) us eus)
    first_wildcard_certs

let first_wildcard_cert_ca_test (ca, x) =
  List.flatten
    (List.map
       (fun (name, _, _) ->
        let c = first_cert name in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        ("certificate verification testing using CA " ^ x ^ " and *.foobar.com "
         >:: strict_test_valid_ca_cert c [] true "*.foobar.com" [ca]) ::
        List.mapi (fun i cn ->
                   "wildcard certificate CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c [] true cn [ca])
                  [ "foo.foobar.com" ; "bar.foobar.com" ; "foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "wildcard certificate CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c [] false cn [ca])
                  [ "foo.foo.foobar.com" ; "bar.fbar.com" ; "com" ; "foobar.com.bla" ]
       )
    first_wildcard_certs)

let intermediate_cas = [
  (true, "cacert") ;
  (true, "cacert-any-ext") ;
  (false, "cacert-ba-false") ;
  (false, "cacert-no-bc") ;
  (false, "cacert-no-keyusage") ;
  (true, "cacert-ku-critical") ;
  (true, "cacert-timestamp") ; (* if we require CAs to have ext_key_usage any, github.com doesn't talk to us *)
  (false, "cacert-unknown") ;
  (false, "cacert-v1")
]

let im_cert name =
  Cert.of_pem_cstruct1 (load ("intermediate/" ^ name))

let second_certs = [
  ("second", [ "second.foobar.com" ], true,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ("second-any", [ "second.foobar.com" ], true,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], Some [ `Any ] ) ;
  ("second-subj", [ "second.foobar.com" ; "foobar.com" ; "foo.foobar.com" ], true,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ("second-unknown-noncrit", [ "second.foobar.com" ], true,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ("second-nonrepud", [ "second.foobar.com" ], true,
   [ `ContentCommitment ], None ) ;
  ("second-time", [ "second.foobar.com" ], true,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], Some [ `TimeStamping ]) ;
  ("second-subj-wild", [ "second.foobar.com" ; "foo.foobar.com" ], true,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ("second-bc-true", [ "second.foobar.com" ], false,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ("second-unknown", [ "second.foobar.com" ], false,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ("second-no-cn", [ ], false,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
  ("second-subjaltemail", [ "second.foobar.com" ], true,
   [ `DigitalSignature ; `ContentCommitment ; `KeyEncipherment ], None ) ;
]

let second_cert name =
  Cert.of_pem_cstruct1 (load ("intermediate/second/" ^ name))

let second_cert_tests =
  List.mapi
    (fun i (name, _, _, us, eus) ->
     "second certificate property testing " ^ string_of_int i >:: test_cert (second_cert name) us eus)
    second_certs

let second_cert_ca_test (cavalid, ca, x) =
  List.flatten
    (List.flatten
       (List.map
          (fun (imvalid, im) ->
           let chain = [im_cert im] in
           List.map
             (fun (name, cns, valid, _, _) ->
              let c = second_cert name in
              ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
              ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
              List.mapi (fun i cn ->
                         "certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                         >:: strict_test_valid_ca_cert c chain (cavalid && imvalid && valid) cn [ca])
                        cns @
              List.mapi (fun i cn ->
                         "certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                         >:: wildcard_test_valid_ca_cert c chain (cavalid && imvalid && valid) cn [ca])
                        cns)
             second_certs)
          intermediate_cas))

let im_ca_tests f =
  List.flatten (List.map f
                         [ (true, cacert, "cacert") ;
                           (true, cacert_ext, "cacert_ext") ;
                           (true, cacert_ext_ku, "cacert_ext_ku") ;
                           (true, cacert_v1, "cacert_v1") ;
                           (false, cacert_pathlen0, "cacert_pathlen0") ])

let second_wildcard_cert_ca_test (cavalid, ca, x) =
  List.flatten
    (List.map
       (fun (imvalid, im) ->
        let chain = [im_cert im] in
        let c = second_cert "second-subj-wild" in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "wildcard certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c chain (cavalid && imvalid) cn [ca])
                  [ "a.foobar.com" ; "foo.foobar.com" ; "foobar.foobar.com" ; "foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "wildcard certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c chain false cn [ca])
                  [ "a.b.foobar.com" ; "f.foobar.com.com" ; "f.f.f." ; "foobar.com.uk" ; "foooo.bar.com" ])
       intermediate_cas)

let second_no_cn_cert_ca_test (cavalid, ca, x) =
  List.flatten
    (List.map
       (fun (imvalid, im) ->
        let chain = [im_cert im] in
        let c = second_cert "second-no-cn" in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: strict_test_valid_ca_cert c chain false cn [ca])
                  [ "a.foobar.com" ; "foo.foobar.com" ; "foobar.foobar.com" ; "foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c chain false cn [ca])
                  [ "a.b.foobar.com" ; "f.foobar.com.com" ; "f.f.f." ; "foobar.com.uk" ; "foooo.bar.com" ])
       intermediate_cas)

let invalid_tests =
  let c = second_cert "second" in
  let h = "second.foobar.com" in
  [
    "invalid chain" >:: strict_test_valid_ca_cert c [] false h [cacert] ;
    "broken chain" >:: strict_test_valid_ca_cert c [cacert] false h [cacert] ;
    "no trust anchor" >:: strict_test_valid_ca_cert c [im_cert "cacert"] false h [] ;
    "not a CA" >:: (fun _ -> assert_equal (List.length (valid_cas ~time:0 [im_cert "cacert"])) 0) ;
    "not a CA" >:: (fun _ -> assert_equal (List.length (valid_cas ~time:0 [c])) 0) ;
  ]

let x509_tests =
  invalid_ca_tests @ valid_ca_tests @
  first_cert_tests @ (ca_tests first_cert_ca_test) @
  first_wildcard_cert_tests @ (ca_tests first_wildcard_cert_ca_test) @
  second_cert_tests @ (im_ca_tests second_cert_ca_test) @ (im_ca_tests second_wildcard_cert_ca_test) @
  (im_ca_tests second_no_cn_cert_ca_test) @
  invalid_tests
