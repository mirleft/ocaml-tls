open Async.Std

(** X.509 certificate handling using Lwt. *)

(** private material: a certificate chain and a RSA private key *)
type priv          = X509.t list * Nocrypto.Rsa.priv

(** authenticator *)
type authenticator = X509.Authenticator.a

(** [private_of_pems ~cert ~priv_key] is [priv], after reading the
    private key and certificate chain from the given PEM-encoded
    files. *)
val private_of_pems : cert:string -> priv_key:string -> priv Deferred.t

(** [certs_of_pem file] is [certificates], which are read from the
    PEM-encoded [file]. *)
val certs_of_pem     : string -> X509.t list Deferred.t

(** [certs_of_pem_dir dir] is [certificates], which are read from all
    PEM-encoded files in [dir]. *)
val certs_of_pem_dir : string -> X509.t list Deferred.t

(** [authenticator methods] constructs an [authenticator] using the
    specified method and data. *)
val authenticator :
  [ `Ca_file of string
  | `Ca_dir  of string
  | `Key_fingerprints of Nocrypto.Hash.hash * (string * Cstruct.t) list
  | `Hex_key_fingerprints of Nocrypto.Hash.hash * (string * string) list
  | `No_authentication_I'M_STUPID ]
  -> authenticator Deferred.t
