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

(** [supported_ciphers] is a list of support ciphers by this library *)
val supported_ciphers : ciphersuite list

(** [supported_hashes] is a list of supported hash algorithms by this library *)
val supported_hashes  : hash_algorithm list

(** [min_dh_size] is minimal diffie hellman group size in bits (currently 512) *)
val min_dh_size : int

(** [min_rsa_key_size] is minimal RSA modulus key size in bits (currently 1024) *)
val min_rsa_key_size : int

(** opaque type of a client configuration *)
type client

(** opaque type of a server configuration *)
type server

(** [peer client name] is [client] with [name] as [peer_name] *)
val peer : client -> string -> client

(** [of_client client] is a client configuration for [client] *)
val of_client : client -> config

(** [of_server server] is a server configuration for [server] *)
val of_server : server -> config

(** [client_exn ?ciphers ?version ?hashes ?rekeying ?validator ?require_secure_rekeying] is [client] configuration with the given parameters *)
(** @raise Invalid_configuration when the configuration is not valid *)
val client_exn :
  ?ciphers   : ciphersuite list ->
  ?version   : tls_version * tls_version ->
  ?hashes    : hash_algorithm list ->
  ?rekeying  : bool ->
  ?validator : X509.Validator.t ->
  ?require_secure_rekeying : bool ->
  unit -> client

(** [server_exn ?ciphers ?version ?hashes ?rekeying ?certificate ?require_secure_rekeying] is [server] configuration with the given parameters *)
(** @raise Invalid_configuration when the configuration is not valid *)
val server_exn :
  ?ciphers     : ciphersuite list ->
  ?version     : tls_version * tls_version ->
  ?hashes      : hash_algorithm list ->
  ?rekeying    : bool ->
  ?certificate : own_cert ->
  ?require_secure_rekeying : bool ->
  unit -> server

open Sexplib
val sexp_of_config : config -> Sexp.t
val config_of_sexp : Sexp.t -> config
