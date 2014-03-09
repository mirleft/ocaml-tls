open Lwt

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C: V1_LWT.CONSOLE) (S: V1_LWT.STACKV4) = struct

  module TLS = Tls.Server

  let on_connect c flow =
    let rec loop tls =
      S.TCPV4.read flow >>= function
        | `Eof     -> C.log_s c (red "read: eof")
        | `Error e -> C.log_s c (red "read: error")
        | `Ok buf  ->
            match TLS.handle_tls tls buf with
              | `Ok (tls', ans) -> S.TCPV4.write flow ans >> loop tls'
              | `Fail err       -> S.TCPV4.write flow err
    in
    let (dst, dst_port) = S.TCPV4.get_dest flow in
    C.log_s c (green "new tcp connection from %s %d"
                (Ipaddr.V4.to_string dst) dst_port)
    >>
      loop Tls.Flow.empty_state

  let start c s =
    S.listen_tcpv4 s ~port:4433 (on_connect c) ;
    S.listen s

end
