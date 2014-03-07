open Lwt

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C: V1_LWT.CONSOLE) (S: V1_LWT.STACKV4) = struct

  let on_connect hello c (flow : S.TCPV4.flow) =
    let rec loop tls =
      S.TCPV4.read flow >>= function
        | `Eof     -> C.log_s c (red "read: eof")
        | `Error e -> C.log_s c (red "read: error")
        | `Ok buf  ->
            let tls', ans = Tls.Client.handle_tls tls buf in
            S.TCPV4.write flow ans >> loop tls'
    in
    let (dst, dst_port) = S.TCPV4.get_dest flow in
    let (tls', ans) = Tls.Client.handle_tls Tls.Flow.empty_state hello in
    C.log_s c (green "writing to tcp connection from %s %d (len %d)"
                     (Ipaddr.V4.to_string dst) dst_port (Cstruct.len ans))
    >>
    S.TCPV4.write flow ans
    >>
    loop tls'

  let start c s =
(*    OS.Time.sleep 5.0 >>= fun () -> *)
    let ip = Ipaddr.V4.make (* 173 194 41 148 *) 193 110 90 23 (* 127 0 0 1 *) in
    C.log_s c (green "connecting to host") >>
      S.TCPV4.create_connection (S.tcpv4 s) (ip, (* 4433 *)(* 443 *) 5223 ) >>= function
       | `Ok flow ->
          C.log_s c (green "established connection") >>
          let client_hello = Tls.Client.open_connection (Some "jabber.ccc.de") in
          on_connect client_hello c flow;
       | `Error e ->
          C.log_s c (red "received an error while connecting")

end
