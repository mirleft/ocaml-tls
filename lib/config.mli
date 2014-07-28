open Core

(** Configuration of the TLS stack *)

(** during validating a configuration, this exception might occur *)
exception Invalid_configuration of string

(** certificate chain and private key of the first certificate *)
type own_cert = Certificate.certificate list * Nocrypto.RSA.priv

(** configuration parameters *)
type config = private {
  ciphers           : Ciphersuite.ciphersuite list ; (** ordered list (regarding preference) of supported cipher suites *)
  protocol_versions : tls_version * tls_version ; (** supported protocol versions (min, max) *)
  hashes            : Packet.hash_algorithm list ; (** ordered list of supported hash algorithms (regarding preference) *)
  use_reneg         : bool ; (** endpoint should accept renegotiation requests *)
  secure_reneg      : bool ; (** other end must use secure renegotiation (RFC 5746) *)
  authenticator     : X509.Authenticator.t option ; (** optional X509 authenticator *)
  peer_name         : string option ; (** optional name of other endpoint (used for SNI RFC4366) *)
  own_certificate   : own_cert option ; (** optional certificate chain *)
}

module Ciphers : sig

  open Ciphersuite

  (** Cipher selection related utilities. *)

  val supported : ciphersuite list
  (** All the ciphers this library can use. *)

  val pfs : ciphersuite list
  (** All the PFS ciphers this library can use. *)

  val pfs_of : ciphersuite list -> ciphersuite list
  (** [pfs_of ciphers] selects only PFS ciphers. *)
end

(** [supported_hashes] is a list of supported hash algorithms by this library *)
val supported_hashes  : Packet.hash_algorithm list

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

(** [client_exn ?ciphers ?version ?hashes ?reneg ?validator ?secure_reneg] is [client] configuration with the given parameters *)
(** @raise Invalid_configuration when the configuration is not valid *)
val client_exn :
  ?ciphers       : Ciphersuite.ciphersuite list ->
  ?version       : tls_version * tls_version ->
  ?hashes        : Packet.hash_algorithm list ->
  ?reneg         : bool ->
  ?authenticator : X509.Authenticator.t ->
  ?secure_reneg  : bool ->
  unit -> client

(** [server_exn ?ciphers ?version ?hashes ?reneg ?certificate ?secure_reneg] is [server] configuration with the given parameters *)
(** @raise Invalid_configuration when the configuration is not valid *)
val server_exn :
  ?ciphers      : Ciphersuite.ciphersuite list ->
  ?version      : tls_version * tls_version ->
  ?hashes       : Packet.hash_algorithm list ->
  ?reneg        : bool ->
  ?certificate  : own_cert ->
  ?secure_reneg : bool ->
  unit -> server

open Sexplib
val sexp_of_config : config -> Sexp.t
val config_of_sexp : Sexp.t -> config
