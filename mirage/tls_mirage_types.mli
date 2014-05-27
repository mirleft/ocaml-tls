
module type TLS_core = sig

  module TCP : V1_LWT.TCPV4

  type error = TCP.error
  type flow

  type cert       = Tls.X509.Cert.t * Tls.X509.PK.t
  type server_cfg = cert
  type client_cfg = cert option * Tls.X509.Validator.t

  val read   : flow -> [> `Ok of Cstruct.t | `Eof | `Error of error ] Lwt.t
  val write  : flow -> Cstruct.t -> unit Lwt.t
  val writev : flow -> Cstruct.t list -> unit Lwt.t
  val close  : flow -> unit Lwt.t

  val client_of_tcp_flow : client_cfg -> string -> TCP.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t
  val server_of_tcp_flow : server_cfg -> TCP.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t
end
