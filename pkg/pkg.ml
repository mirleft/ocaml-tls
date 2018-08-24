#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let lwt = Conf.with_pkg ~default:false "lwt"
let mirage = Conf.with_pkg ~default:false "mirage"

let opams =
  let lint_deps_excluding = Some ["ounit"; "oUnit"; "ppx_deriving"] in
  [Pkg.opam_file ~lint_deps_excluding "opam"]

let () =
  Pkg.describe ~opams "tls" @@ fun c ->
  let lwt = Conf.value c lwt
  and mirage = Conf.value c mirage
  in
  let exts = Exts.(cmx @ library @ exts [".cmi" ; ".cmt" ]) in
  Ok [
    Pkg.lib ~exts "lib/tls" ;
    Pkg.mllib ~cond:lwt "lwt/tls-lwt.mllib" ;
    Pkg.mllib ~cond:mirage "mirage/tls-mirage.mllib" ;
    Pkg.test "tests/unittestrunner" ;
    Pkg.test ~run:false "tests/feedback" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/starttls_server" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/echo_server" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/echo_server_sni" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/echo_server_alpn" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/echo_client" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/echo_client_alpn" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/test_server" ;
    Pkg.test ~run:false ~cond:lwt "lwt/examples/test_client" ;
  ]
