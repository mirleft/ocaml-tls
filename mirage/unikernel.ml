open Lwt

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C: V1_LWT.CONSOLE) (S: V1_LWT.STACKV4) = struct

  let handle_data = Tls.Flow.Server.handle_tls

  let rec handle_and_send state buf flow =
    Cstruct.hexdump buf;
    let answer, len = handle_data state buf in
    Lwt_list.iter_s (S.TCPV4.write flow) answer
    >>
      if Cstruct.len buf > len then
        handle_and_send state (Cstruct.shift buf len) flow
      else return ()


  let handle state c flow =
    Printf.printf "handling\n";
    S.TCPV4.read flow
    >>= function
      | `Ok b -> handle_and_send state b flow
      | `Eof -> C.log_s c (red "read: eof")
      | `Error e -> C.log_s c (red "read: error")

  let start c s =
    S.listen_tcpv4 s ~port:80
                   (fun flow ->
                    let state = Tls.Flow.Server.make () in
                    let dst, dst_port = S.TCPV4.get_dest flow in
                    C.log_s c (green "new tcp connection from %s %d"
                                     (Ipaddr.V4.to_string dst) dst_port)
                    >> handle state c flow
                    >> handle state c flow
                    >> handle state c flow
                    >> handle state c flow
                    >> handle state c flow
                    >> S.TCPV4.close flow
    );

    S.listen s

end
