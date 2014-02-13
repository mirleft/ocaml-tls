open Lwt
module P = Tls.Packet

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C: V1_LWT.CONSOLE) (S: V1_LWT.STACKV4) = struct

  let start c s =
    S.listen_tcpv4 s ~port:80 (fun flow ->
        let dst, dst_port = S.TCPV4.get_dest flow in
        C.log_s c (green "new tcp connection from %s %d"
                     (Ipaddr.V4.to_string dst) dst_port)
        >>= fun () ->
        S.TCPV4.read flow
        >>= function
        | `Ok b ->
           let (header, body, rest) = P.parse b in
           Cstruct.hexdump rest ;
           C.log_s c
                   (yellow "read: %d\n %s body %s (rest: %d)"
                           (Cstruct.len b) (P.header_to_string header) (P.handshake_to_string body) (Cstruct.len rest))
           >>= fun () ->
           S.TCPV4.close flow

        | `Eof -> C.log_s c (red "read: eof")

        | `Error e -> C.log_s c (red "read: error")
      );

    S.listen s

end
