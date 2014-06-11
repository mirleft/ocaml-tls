
type priv      = X509.Cert.t list * X509.PK.t
type validator = X509.Validator.t

val private_of_pems : cert:Lwt_io.file_name -> priv_key:Lwt_io.file_name -> priv Lwt.t

val certs_of_pem     : Lwt_io.file_name -> X509.Cert.t list Lwt.t
val certs_of_pem_dir : Lwt_io.file_name -> X509.Cert.t list Lwt.t

val validator :
  [ `Ca_file of Lwt_io.file_name
  | `Ca_dir  of Lwt_io.file_name
  | `No_validation_I'M_STUPID ]
  -> validator Lwt.t

