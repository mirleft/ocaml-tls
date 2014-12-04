
type priv          = X509.Cert.t list * X509.PK.t
type authenticator = X509.Authenticator.t

val private_of_pems : cert:Lwt_io.file_name -> priv_key:Lwt_io.file_name -> priv Lwt.t

val certs_of_pem     : Lwt_io.file_name -> X509.Cert.t list Lwt.t
val certs_of_pem_dir : Lwt_io.file_name -> X509.Cert.t list Lwt.t

val authenticator :
  [ `Ca_file of Lwt_io.file_name
  | `Ca_dir  of Lwt_io.file_name
  | `Fingerprint of string
  | `No_authentication_I'M_STUPID ]
  -> authenticator Lwt.t

