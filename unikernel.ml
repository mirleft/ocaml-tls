open Lwt
module P = Tls.Packet

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C: V1_LWT.CONSOLE) (S: V1_LWT.STACKV4) = struct
(*
  let client mgr src_ip dest_ip dport =
    let payload chan =
      let a = Cstruct.sub (OS.Io_page.(to_cstruct (get 1))) 0 200 in
      let r = Cstruct.sub (OS.Io_page.(to_cstruct (get 1))) 0 28 in
      let len = assemble_client_hello (Cstruct.shift a 5) { major = 3; minor = 1; time = 0; random = r; sessionid = None; ciphersuites = []; compression_methods = []; extensions = [] };
      assemble_hdr buf { content_type = HANDSHAKE; major = 3; minor = 1 } len;
      Net.Flow.write chan a >>
      Net.Flow.close chan
    in
    lwt conn = Net.Flow.connect mgr (`TCPv4 (Some (Some src_ip, 0), (dest_ip, dport), payload)) in
    printf "client done!\n"
    return ();
 *)
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
           Cstruct.hexdump rest;
           C.log_s c
                   (yellow "read: %d\n %s body %s (rest: %d)"
                           (Cstruct.len b) (P.header_to_string header) (P.body_to_string body) (Cstruct.len rest))
           >>
             let answerp = P.answer body in
             Cstruct.hexdump answerp;
             let (header, body, rest) = P.parse answerp in
             C.log_s c
                     (yellow "answering: %d\n %s body %s rest %d"
                             (Cstruct.len answerp) (P.header_to_string header) (P.body_to_string body) (Cstruct.len rest))
             >>
               S.TCPV4.write flow answerp
             >>
               S.TCPV4.close flow

        | `Eof -> C.log_s c (red "read: eof")

        | `Error e -> C.log_s c (red "read: error")
      );

    S.listen s

end
