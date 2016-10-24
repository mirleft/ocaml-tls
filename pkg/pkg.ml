#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let lwt = Conf.with_pkg ~default:false "lwt"
let mirage = Conf.with_pkg ~default:false "mirage"

let () =
  let lint_deps_excluding =
    Some ["io-page" ; "ppx_tools" ; "ipaddr" ; "ounit" ; "oUnit"]
  in
  let opams = [ Pkg.opam_file "opam" ~lint_deps_excluding ] in
  Pkg.describe ~opams "tls" @@ fun c ->
  let lwt = Conf.value c lwt
  and mirage = Conf.value c mirage
  in
  Ok [
    Pkg.mllib ~api:["Tls"] "lib/tls.mllib" ;
    Pkg.mllib ~cond:lwt "lwt/tls-lwt.mllib" ;
    Pkg.mllib ~cond:mirage "mirage/tls-mirage.mllib" ;
    Pkg.test "tests/unittestrunner" ;
    Pkg.test ~run:false "tests/feedback" ;
    Pkg.test ~cond:lwt ~run:false "lwt/examples/starttls_server" ;
    Pkg.test ~cond:lwt ~run:false "lwt/examples/echo_server" ;
    Pkg.test ~cond:lwt ~run:false "lwt/examples/echo_server_sni" ;
    Pkg.test ~cond:lwt ~run:false "lwt/examples/echo_client" ;
    Pkg.test ~cond:lwt ~run:false "lwt/examples/http_client" ;
    Pkg.test ~cond:lwt ~run:false "lwt/examples/test_client" ;
    Pkg.test ~cond:lwt ~run:false "lwt/examples/test_server" ;
  ]
