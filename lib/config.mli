open Core
open Ciphersuite

(** Configuration of the TLS stack *)

(** during validating a configuration, this exception might occur *)
exception Invalid_configuration of string

(** certificate chain and private key of the first certificate *)
type own_cert = Certificate.certificate list * Nocrypto.RSA.priv

(** configuration parameters *)
type config = private {
  ciphers                 : ciphersuite list ; (** ordered list (regarding preference) of supported cipher suites *)
  protocol_versions       : tls_version * tls_version ; (** supported protocol versions (max, min) *)
  hashes                  : hash_algorithm list ; (** ordered list of supported hash algorithms (regarding preference) *)
  use_rekeying            : bool ; (** endpoint should accept rekeying requests *)
  require_secure_rekeying : bool ; (** other end must use secure rekeying (RFC 5746) *)
  validator               : X509.Validator.t option ; (** optional X509 validator *)
  peer_name               : string option ; (** optional name of other endpoint (used for SNI RFC4366) *)
  own_certificate         : own_cert option ; (** optional certificate chain *)
}

(** @return list of support ciphers by this library *)
val supported_ciphers : ciphersuite list

(** @return list of supported hash algorithms by this library *)
val supported_hashes  : hash_algorithm list

(** @return minimal diffie hellman group size in bits *)
val min_dh_size : int

(** @return minimal RSA modulus key size in bits *)
val min_rsa_key_size : int

(** opaque type of a client configuration *)
type client

(** opaque type of a server configuration *)
type server

(** given a client and a name *)
(** @return a new client whose peer_name is name *)
val peer : client -> string -> client

(** given a client configuration *)
(** @return config *)
val of_client : client -> config

(** given a server configuration *)
(** @return config *)
val of_server : server -> config

(** given some optional configuration arguments *)
(** @return a client *)
(** @raise Invalid_configuration when the configuration is not valid *)
val client_exn :
  ?ciphers   : ciphersuite list ->
  ?version   : tls_version * tls_version ->
  ?hashes    : hash_algorithm list ->
  ?rekeying  : bool ->
  ?validator : X509.Validator.t ->
  ?require_secure_rekeying : bool ->
  unit -> client

(** given some optional configuration arguments *)
(** @return a server *)
(** @raise Invalid_configuration when the configuration is not valid *)
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
