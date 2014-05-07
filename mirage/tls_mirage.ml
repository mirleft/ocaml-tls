
open Mirage_sig

module type TCPV4' =
  TCPV4 with type buffer = Cstruct.t
         and type 'a io  = 'a Lwt.t

module TLS ( TCP : TCPV4' ) = struct

  type +'a io = 'a TCP.io

  type t      = TCP.t

  type error  = TCP.error

  type flow = {
    role           : [ `Server
                     | `Client ] ;
    tcp            : TCP.flow ;
    mutable state  : [ `Active of Tls.Flow.state
                     | `Eof
                     | `Error of error ] ;
    mutable linger : Cstruct.t list ;
  }


end
