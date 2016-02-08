open Nocrypto
open Core

(** Configuration of the TLS stack *)

(** {1 Config type} *)

(** certificate chain and private key of the first certificate *)
type certchain = X509.t list * Nocrypto.Rsa.priv

(** polymorphic variant of own certificates *)
type own_cert = [
  | `None
  | `Single of certchain
  | `Multiple of certchain list
  | `Multiple_default of certchain * certchain list
]

type session_cache = SessionID.t -> epoch_data option

type psk_cache = PreSharedKeyID.t -> epoch_data option

(** configuration parameters *)
type config = private {
  ciphers           : Ciphersuite.ciphersuite list ; (** ordered list (regarding preference) of supported cipher suites *)
  protocol_versions : tls_version * tls_version ; (** supported protocol versions (min, max) *)
  hashes            : Hash.hash list ; (** ordered list of supported hash algorithms (regarding preference) *)
  use_reneg         : bool ; (** endpoint should accept renegotiation requests *)
  authenticator     : X509.Authenticator.a option ; (** optional X509 authenticator *)
  peer_name         : string option ; (** optional name of other endpoint (used for SNI RFC4366) *)
  own_certificates  : own_cert ; (** optional default certificate chain and other certificate chains *)
  session_cache     : session_cache ;
  psk_cache         : psk_cache ;
  cached_session    : epoch_data option ;
  groups            : group list ;
}

val config_of_sexp : Sexplib.Sexp.t -> config
val sexp_of_config : config -> Sexplib.Sexp.t

(** opaque type of a client configuration *)
type client

val client_of_sexp : Sexplib.Sexp.t -> client
val sexp_of_client : client -> Sexplib.Sexp.t

(** opaque type of a server configuration *)
type server

val server_of_sexp : Sexplib.Sexp.t -> server
val sexp_of_server : server -> Sexplib.Sexp.t

(** {1 Constructors} *)

(** [client authenticator ?ciphers ?version ?hashes ?reneg ?certificates] is [client] configuration with the given parameters *)
(** @raise Invalid_argument if the configuration is invalid *)
val client :
  authenticator   : X509.Authenticator.a ->
  ?ciphers        : Ciphersuite.ciphersuite list ->
  ?version        : tls_version * tls_version ->
  ?hashes         : Hash.hash list ->
  ?reneg          : bool ->
  ?certificates   : own_cert ->
  ?cached_session : epoch_data ->
  ?groups         : Dh.group list ->
  unit -> client

(** [server ?ciphers ?version ?hashes ?reneg ?certificates ?authenticator] is [server] configuration with the given parameters *)
(** @raise Invalid_argument if the configuration is invalid *)
val server :
  ?ciphers       : Ciphersuite.ciphersuite list ->
  ?version       : tls_version * tls_version ->
  ?hashes        : Hash.hash list ->
  ?reneg         : bool ->
  ?certificates  : own_cert ->
  ?authenticator : X509.Authenticator.a ->
  ?session_cache : session_cache ->
  ?psk_cache     : psk_cache ->
  ?groups        : Dh.group list ->
  unit -> server

(** [peer client name] is [client] with [name] as [peer_name] *)
val peer : client -> string -> client

(** {1 Utility functions} *)

(** [default_hashes] is a list of hash algorithms used by default *)
val default_hashes  : Hash.hash list

(** [supported_hashes] is a list of supported hash algorithms by this library *)
val supported_hashes  : Hash.hash list

val tls13_hashes : Hash.hash list

(** [min_dh_size] is minimal diffie hellman group size in bits (currently 1024) *)
val min_dh_size : int

(** [dh_group] is the default Diffie-Hellman group (currently the
ffdhe2048 group from
{{:https://www.ietf.org/id/draft-ietf-tls-negotiated-ff-dhe-10.txt}Negotiated
Finite Field Diffie-Hellman Ephemeral Parameters for TLS}) *)
val dh_group : Dh.group

val supported_groups : Dh.group list

(** [min_rsa_key_size] is minimal RSA modulus key size in bits (currently 1024) *)
val min_rsa_key_size : int

(** Cipher selection *)
module Ciphers : sig

  open Ciphersuite

  (** Cipher selection related utilities. *)

  (** {1 Cipher selection} *)

  val default : ciphersuite list
  (** [default] is a list of ciphersuites this library uses by default. *)

  val supported : ciphersuite list
  (** [supported] is a list of ciphersuites this library supports
      (larger than [default]). *)

  val fs : ciphersuite list
  (** [fs] is a list of ciphersuites which provide forward secrecy
      (sublist of [default]). *)

  val fs_of : ciphersuite list -> ciphersuite list
  (** [fs_of ciphers] selects all ciphersuites which provide forward
      secrecy from [ciphers]. *)

  val psk : ciphersuite list
  (** [psk] is a list of ciphersuites which use a pre-shared key (sublist of [default]). *)

  val psk_of : ciphersuite list -> ciphersuite list
  (** [psk_of ciphers] selects all ciphersuites which use a pre-shared key. *)

end

(** {1 Internal use only} *)

(** [of_client client] is a client configuration for [client] *)
val of_client : client -> config

(** [of_server server] is a server configuration for [server] *)
val of_server : server -> config

