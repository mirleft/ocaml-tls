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
            match Tls.Client.handle_tls tls buf with
              | `Ok (tls', ans) -> S.TCPV4.write flow ans >> loop tls'
              | `Fail err       -> S.TCPV4.write flow err
    in
    let (dst, dst_port) = S.TCPV4.get_dest flow in
    match Tls.Client.handle_tls Tls.Flow.empty_state hello with
    | `Ok (tls', ans) ->
       C.log_s c (green "writing to tcp connection from %s %d (len %d)"
                        (Ipaddr.V4.to_string dst) dst_port (Cstruct.len ans))
       >>
         S.TCPV4.write flow ans
       >>
         loop tls'
    | `Fail err ->
       C.log_s c (red "fail to tcp connection from %s %d (len %d)"
                      (Ipaddr.V4.to_string dst) dst_port (Cstruct.len err))
       >>
         S.TCPV4.write flow err

  let start c s =
(*    OS.Time.sleep 5.0 >>= fun () -> *)
    let google, gport, gname = ((Ipaddr.V4.make 173 194 41 148), 443, Some "www.google.com") in
    let jabberccc, jport, jname = ((Ipaddr.V4.make 173 194 41 148), 5223, Some "jabber.ccc.de") in
    let localssl, lport, lname = ((Ipaddr.V4.make 127 0 0 1), 4433, None) in
    C.log_s c (green "connecting to host") >>
      S.TCPV4.create_connection (S.tcpv4 s) (google, gport) >>= function
       | `Ok flow ->
          C.log_s c (green "established connection") >>
          let client_hello = Tls.Client.open_connection gname in
          on_connect client_hello c flow;
       | `Error e ->
          C.log_s c (red "received an error while connecting")

end
