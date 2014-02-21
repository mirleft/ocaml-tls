open Lwt

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C: V1_LWT.CONSOLE) (S: V1_LWT.STACKV4) = struct

  module TLS = Tls.Flow.Server

  let on_connect c flow =
    let rec loop tls =
      S.TCPV4.read flow >>= function
        | `Eof     -> C.log_s c (red "read: eof")
        | `Error e -> C.log_s c (red "read: error")
        | `Ok buf  ->
            let (tls', ans) = TLS.handle_tls tls buf in
            S.TCPV4.write flow ans >> loop tls'
    in
    let (dst, dst_port) = S.TCPV4.get_dest flow in
    lwt () =
      C.log_s c (green "new tcp connection from %s %d"
                  (Ipaddr.V4.to_string dst) dst_port)
    in
    try_lwt loop TLS.empty_state 
    finally S.TCPV4.close flow

  let start c s =
    S.listen_tcpv4 s ~port:80 (on_connect c) ;
    S.listen s

end
