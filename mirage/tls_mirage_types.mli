
module type TLS_core = sig

  module TCP : V1_LWT.TCPV4

  type error = TCP.error
  type flow

  val read   : flow -> [> `Ok of Cstruct.t | `Eof | `Error of error ] Lwt.t
  val write  : flow -> Cstruct.t -> unit Lwt.t
  val writev : flow -> Cstruct.t list -> unit Lwt.t
  val close  : flow -> unit Lwt.t
  val rekey  : flow -> unit Lwt.t

  type tracer = Sexplib.Sexp.t -> unit

  val client_of_tcp_flow :
    ?trace:tracer -> Tls.Config.client -> string -> TCP.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t
  val server_of_tcp_flow :
    ?trace:tracer -> Tls.Config.server -> TCP.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t
end
