
module Make(TCP : V1_LWT.TCPV4) : sig

  type +'a io = 'a Lwt.t
  type t      = TCP.t
  type error  = TCP.error

  type buffer   = Cstruct.t
  type ipv4addr = TCP.ipv4addr

  type cert = Tls.X509.Cert.t * Tls.X509.PK.t
  type server_cfg = cert
  type client_cfg = cert option * Tls.X509.Validator.t

  type flow

  val read   : flow -> [`Ok of buffer | `Eof | `Error of error ] io
  val write  : flow -> buffer -> unit io
  val writev : flow -> buffer list -> unit io
  val close  : flow -> unit io

  val create_connection : t -> client_cfg -> string -> ipv4addr * int ->
    [ `Ok of flow | `Error of error ] io

  val server_of_tcp_flow : server_cfg -> TCP.flow ->
    [ `Ok of flow | `Error of error ] io

end
