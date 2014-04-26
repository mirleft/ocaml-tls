
type cert = Tls.X509.Cert.t * Tls.X509.PK.t

val cert_of_pems : cert:Lwt_io.file_name -> priv_key:Lwt_io.file_name -> cert Lwt.t

