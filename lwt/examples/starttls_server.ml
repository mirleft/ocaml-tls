open Lwt

let capability = "[CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] server ready.\r\n"

let ok_starttls = "OK STARTTLS\r\n"

let cert () =
  X509_lwt.private_of_pems
  ~cert:"./certificates/server.pem"
  ~priv_key:"./certificates/server.key"

let init_socket addr port =
  let sockaddr = Unix.ADDR_INET (Unix.inet_addr_of_string addr, port) in
  let socket = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt socket Unix.SO_REUSEADDR true;
  Lwt_unix.bind socket sockaddr;
  socket

let create_srv_socket addr port =
  let socket = init_socket addr port in
  Lwt_unix.listen socket 10;
  socket

let accept sock =
  Lwt_unix.accept sock >>= fun (sock_cl, addr) ->
  let ic = Lwt_io.of_fd ~close:(fun() -> return()) ~mode:Lwt_io.input sock_cl in
  let oc = Lwt_io.of_fd ~close:(fun() -> return()) ~mode:Lwt_io.output sock_cl in
  return ((ic,oc), addr, sock_cl)

let start_server () =
  let write oc buff =
    Lwt_io.write oc buff >> Lwt_io.flush oc
  in
  let read ic =
    Lwt_io.read ic ~count:2048 >>= fun buff ->
    Printf.printf "%s%!" buff;
    return buff
  in
  let parse buff = 
    try 
      let _ = Str.search_forward (Str.regexp "^\\([^ ]+ \\)\\([^ ]+\\)\r\n$") buff 0
      in
      Str.matched_group 1 buff, Str.matched_group 2 buff
    with _ -> "","" 
  in
  let rec wait_cmd sock_cl ic oc =
    read ic >>= fun buff -> 
    let tag,cmd = parse buff in
    match cmd with
    | "CAPABILITY" ->
      write oc ("* " ^ capability ^ tag ^ " OK CAPABILITY\r\n") >>
      wait_cmd sock_cl ic oc
    | "STARTTLS" ->
      write oc (tag ^ ok_starttls) >>
      Lwt_io.close ic >>= fun () ->
      Lwt_io.close oc >>= fun () ->
      Tls_lwt.rng_init () >>= fun () ->
      cert () >>= fun cert ->
      Tls_lwt.Unix.server_of_fd 
       (Tls.Config.server ~certificate:cert()) sock_cl >>= fun s ->
      let ic,oc = Tls_lwt.of_t s in
      write oc ("* OK " ^ capability) >>
      wait_cmd sock_cl ic oc
    | _ ->
      write oc ("BAD\r\n") >>
      wait_cmd sock_cl ic oc
  in
  let sock = create_srv_socket "127.0.0.1" 143 in
  accept sock >>= fun ((ic,oc), addr, sock_cl) ->
  write oc ("* OK " ^ capability) >>
  wait_cmd sock_cl ic oc

let () =
  Lwt_main.run (start_server())
