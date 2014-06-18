open Core
open Ciphersuite

exception Invalid_configuration of string

type own_cert = Certificate.certificate list * Nocrypto.RSA.priv

(* some config parameters *)
type config = private {
  (* ordered list (regarding preference) of supported cipher suites *)
  ciphers                 : ciphersuite list ;
  (* (max, min) *)
  protocol_versions       : tls_version * tls_version ;
  (* ordered list (regarding preference) *)
  hashes                  : hash_algorithm list ;
  (* signatures              : Packet.signature_algorithm_type list ; *)
  use_rekeying            : bool ;
  require_secure_rekeying : bool ;
  validator               : X509.Validator.t option ;
  peer_name               : string option ;
  own_certificate         : own_cert option ;
}

val supported_ciphers : ciphersuite list
val supported_hashes  : hash_algorithm list

val min_dh_size : int
val min_rsa_key_size : int

type client
type server

val peer : client -> string -> client

val of_client : client -> config
val of_server : server -> config

val client_exn :
  ?ciphers   : ciphersuite list ->
  ?version   : tls_version * tls_version ->
  ?hashes    : hash_algorithm list ->
  ?rekeying  : bool ->
  ?validator : X509.Validator.t ->
  ?require_secure_rekeying : bool ->
  unit -> client

val server_exn :
  ?ciphers     : ciphersuite list ->
  ?version     : tls_version * tls_version ->
  ?hashes      : hash_algorithm list ->
  ?rekeying    : bool ->
  ?certificate : own_cert ->
  unit -> server

open Sexplib
val sexp_of_config : config -> Sexp.t
val config_of_sexp : Sexp.t -> config
