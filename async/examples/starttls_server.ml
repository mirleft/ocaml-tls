open Core.Std
open Async.Std
open Log.Global

let capability = "[CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] server ready.\r\n"

let ok_starttls = "OK STARTTLS\r\n"

let cert () =
  X509_async.private_of_pems
  ~cert:"./certificates/server.pem"
  ~priv_key:"./certificates/server.key"

(* let init_socket addr port = *)
(*   let sockaddr = Unix.ADDR_INET (Unix.inet_addr_of_string addr, port) in *)
(*   let socket = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in *)
(*   Lwt_unix.setsockopt socket Unix.SO_REUSEADDR true; *)
(*   Lwt_unix.bind socket sockaddr; *)
(*   socket *)

(* let create_srv_socket addr port = *)
(*   let socket = init_socket addr port in *)
(*   Lwt_unix.listen socket 10; *)
(*   socket *)

(* let accept sock = *)
(*   Lwt_unix.accept sock >>= fun (sock_cl, addr) -> *)
(*   let ic = Lwt_io.of_fd ~close:(fun() -> return()) ~mode:Lwt_io.input sock_cl in *)
(*   let oc = Lwt_io.of_fd ~close:(fun() -> return()) ~mode:Lwt_io.output sock_cl in *)
(*   return ((ic,oc), addr, sock_cl) *)

let start_server () =
  let buf = String.create 4096 in
  let write w buff =
    Writer.write w buff ;
    Writer.flushed w
  in
  let read r =
    Reader.read r buf >>| function
    | `Eof -> raise End_of_file
    | `Ok n ->
      let buf = String.subo buf ~len:n in
      printf "%s" buf;
      buf
  in
  let parse buff =
    try
      let _ = Str.search_forward (Str.regexp "^\\([^ ]+ \\)\\([^ ]+\\)\r\n$") buff 0
      in
      Str.matched_group 1 buff, Str.matched_group 2 buff
    with _ -> "",""
  in
  let rec wait_cmd r w =
    read r >>= fun buff ->
    let tag,cmd = parse buff in
    match cmd with
    | "CAPABILITY" ->
      write w ("* " ^ capability ^ tag ^ " OK CAPABILITY\r\n") >>= fun () ->
      wait_cmd r w
    | "STARTTLS" ->
      write w (tag ^ ok_starttls) >>= fun () ->
      (* Lwt_io.close ic >>= fun () -> *)
      (* Lwt_io.close oc >>= fun () -> *)
      cert () >>= fun cert ->
      Tls_async.Unix.create_server
       (Tls.Config.server ~certificates:(`Single cert) ()) r w >>= fun s ->
      Tls_async.of_t s >>= fun (r, w) ->
      write w ("* OK " ^ capability) >>= fun () ->
      wait_cmd r w
    | _ ->
      write w ("BAD\r\n") >>= fun () ->
      wait_cmd r w
  in
  let server_fun _addr r w =
    Writer.write w ("* OK " ^ capability) ;
    Writer.flushed w >>= fun () ->
    wait_cmd r w
  in
  Tcp.(Server.create (on_port 8143) server_fun)

let main () =
  start_server () >>= fun _srv ->
  Deferred.unit

let () =
  don't_wait_for @@ main () ;
  never_returns @@ Scheduler.go ()
