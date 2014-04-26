
open Lwt

type cert = Tls.X509.Cert.t * Tls.X509.PK.t

let read_file path =
  let open Lwt_io in
  lwt file = open_file ~mode:Input path in
  lwt str  = read file in
  close file >> return (Cstruct.of_string str)

let cert_of_pems ~cert ~priv_key =
  lwt cs_cert = read_file cert
  and cs_pk   = read_file priv_key in
  let open Tls.X509 in
  lwt cert =
    try return @@ Cert.of_pem_cstruct1 cs_cert
    with Invalid_argument msg -> fail (Failure ("certificate: " ^ msg))
  and pk   =
    try return @@ PK.of_pem_cstruct1 cs_pk
    with Invalid_argument msg -> fail (Failure ("key: " ^ msg))
  in
  return (cert, pk)

