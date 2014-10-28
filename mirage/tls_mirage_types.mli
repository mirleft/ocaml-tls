
module type TLS_core = sig

  module TCP     : V1_LWT.TCPV4
  module ENTROPY : V1_LWT.ENTROPY

  type error = TCP.error

  include V1_LWT.FLOW
    with type error  := error
     and type 'a io  := 'a Lwt.t
     and type buffer := Cstruct.t

  val attach_entropy : ENTROPY.t -> unit Lwt.t

  val reneg  : flow -> [ `Ok of unit | `Eof | `Error of error ] Lwt.t

  type tracer = Sexplib.Sexp.t -> unit

  val client_of_tcp_flow :
    ?trace:tracer -> Tls.Config.client -> string -> TCP.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t
  val server_of_tcp_flow :
    ?trace:tracer -> Tls.Config.server -> TCP.flow ->
    [> `Ok of flow | `Error of error ] Lwt.t
end
