open Lwt

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
        >>
          S.TCPV4.read flow
        >>= function
          | `Ok b ->
             let s = Tls.Flow.Server.make () in
             C.log_s c (blue "state %s" (Tls.Flow.Server.s_to_string s))
             >>= fun e ->
               Cstruct.hexdump b;
               let answers = List.rev (Tls.Flow.Server.handle_tls s b) in
               Lwt_list.iter_s (fun answer ->
                                    Cstruct.hexdump answer;
                                    C.log_s c (blue "state %s" (Tls.Flow.Server.s_to_string s))
                                    >>
                                      let tls, len = Tls.Reader.parse answer in
                                      C.log_s c
                                              (yellow "answering: %d (len %d)\n %s"
                                                      (Cstruct.len answer) len (Tls.Printer.to_string tls))
                                      >>
                                        S.TCPV4.write flow answer)
                               answers
               >>
                 C.log_s c (blue "state %s" (Tls.Flow.Server.s_to_string s))
               >>
                 S.TCPV4.close flow

        | `Eof -> C.log_s c (red "read: eof")

        | `Error e -> C.log_s c (red "read: error")
      );

    S.listen s

end
