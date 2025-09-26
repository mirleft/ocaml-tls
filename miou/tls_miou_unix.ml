(* NOTE: the unix/tls_unix.ml is mostly copied from here, so any change should be synchronized. *)

let src = Logs.Src.create "tls-miou"

module Log = (val Logs.src_log src : Logs.LOG)

external reraise : exn -> 'a = "%reraise"

let ( $ ) f x = f x

exception Tls_alert of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure
exception Closed_by_peer

let () =
  Printexc.register_printer @@ function
  | Closed_by_peer -> Some "Connection closed by peer"
  | Tls_alert alert -> Some (Tls.Packet.alert_type_to_string alert)
  | Tls_failure failure -> Some (Tls.Engine.string_of_failure failure)
  | _ -> None

type state =
  [ `Active of Tls.Engine.state
  | `Read_closed of Tls.Engine.state
  | `Write_closed of Tls.Engine.state
  | `Closed
  | `Error of exn ]

type t = {
  role : [ `Server | `Client ];
  fd : Miou_unix.file_descr;
  mutable state : state;
  mutable linger : string option;
  read_buffer_size : int;
  buf : bytes;
  mutable rd_closed : bool;
}

let file_descr { fd; _ } = fd

let half_close state mode =
  match (state, mode) with
  | `Active tls, `read -> `Read_closed tls
  | `Active tls, `write -> `Write_closed tls
  | `Active _, `read_write -> `Closed
  | `Read_closed tls, `read -> `Read_closed tls
  | `Read_closed _, (`write | `read_write) -> `Closed
  | `Write_closed tls, `write -> `Write_closed tls
  | `Write_closed _, (`read | `read_write) -> `Closed
  | ((`Closed | `Error _) as e), (`read | `write | `read_write) -> e

let inject_state tls = function
  | `Active _ -> `Active tls
  | `Read_closed _ -> `Read_closed tls
  | `Write_closed _ -> `Write_closed tls
  | (`Closed | `Error _) as e -> e

let tls_alert a = Tls_alert a
let tls_fail f = Tls_failure f
let inhibit fn v = try fn v with _ -> ()

let write flow str =
  Log.debug (fun m -> m "try to write %d byte(s)" (String.length str));
  try Miou_unix.write flow.fd str with
  | Unix.Unix_error ((Unix.EPIPE | Unix.ECONNRESET), _, _) ->
      flow.state <- half_close flow.state `write;
      raise Closed_by_peer
  | Unix.Unix_error (_, _, _) as exn ->
      flow.state <- `Error exn;
      reraise exn

let handle flow tls str =
  match Tls.Engine.handle_tls tls str with
  | Ok (state, eof, `Response resp, `Data data) ->
      Log.debug (fun m -> m "We handled %d byte(s)" (String.length str));
      let state = inject_state state flow.state in
      let state = Option.(value ~default:state (map (fun `Eof -> half_close state `read) eof)) in
      flow.state <- state;
      let to_close = flow.state = `Closed in
      Option.iter (inhibit $ write flow) resp;
      (* NOTE(dinosaure): [write flow] can set [flow.state]. So we must
         check if the actual [flow.state] or the [flow.state] after [write flow]
         want to close the underlying file-descriptor. *)
      if to_close || flow.state = `Closed then Miou_unix.close flow.fd;
      data
  | Error (fail, `Response resp) ->
      let exn = match fail with
        | `Alert a -> tls_alert a | f -> tls_fail f in
      flow.state <- `Error exn;
      let _ = inhibit (write flow) resp in
      raise exn

let read flow =
  match Miou_unix.read flow.fd flow.buf ~off:0 ~len:(Bytes.length flow.buf) with
  | 0 -> Ok String.empty
  | len -> Ok (Bytes.sub_string flow.buf 0 len)
  | exception Unix.Unix_error (Unix.ECONNRESET, _, _) -> Ok String.empty
  | exception exn -> Error exn

let not_errored = function `Error _ -> false | _ -> true

let garbage flow = match flow.linger with
  | Some "" | None -> false
  | _ -> true

let read_react flow =
  match flow.state with
  | `Error exn -> raise exn
  | `Read_closed _ | `Closed when garbage flow ->
    (* XXX(dinosaure): [`Closed] can appear "at the same time" than some
       application-data. In that case, we stored them into [t.linger]. Depending
       on who closed the connection, [read_react] gives this /garbage/ in any
       situation (even if the user closed the connection).

       An extra layer with [read] below check if [`Read_closed]/[`Close] comes
       from the network (the peer closed the connection) or the user. In the
       first case, we must give pending application-data. In the second case,
       we must return [0] (or raise [End_of_file]). *)
    let mbuf = flow.linger in
    flow.linger <- None;
    mbuf
  | `Read_closed _ | `Closed ->
    (* XXX(dinosaure): the goal of [read_react] is to read some encrypted bytes
       and try to decrypt them with [handle]. If the linger is empty, this means
       that we're trying to get more data (to decrypt) when we can't get any
       more. From this point of view, it's an error that needs to be notified.
       However, this error can be interpreted in 2 ways:
       - we want to have more data decrypted. In this case, this error is
         expected and may result in the user being told that there is nothing
         left to read (for example, returning 0).
       - we attempt a handshake. In this case, we are dealing with an unexpected
         error. *)
    raise End_of_file
  | `Active _ | `Write_closed _ ->
    Log.debug (fun m -> m "read something from the TLS session");
    match read flow with
    | Error exn ->
      if not_errored flow.state then flow.state <- `Error exn;
      raise exn
    | Ok "" ->
      (* XXX(dinosaure): see [`Read_closed _ | `Closed] case. *)
      raise End_of_file 
    | Ok str ->
      Log.debug (fun m -> m "got %d byte(s)" (String.length str));
      match flow.state with
      | `Active tls | `Read_closed tls | `Write_closed tls -> handle flow tls str
      | `Closed -> raise End_of_file
      | `Error exn -> raise exn
[@@ocamlformat "disable"]

let rec read_in flow ?(off= 0) ?len buf =
  let len = Option.value ~default:(Bytes.length buf - off) len in
  let write_in res =
    let rlen = String.length res in
    let mlen = min len rlen in
    Bytes.blit_string res 0 buf off mlen;
    let linger = if mlen < rlen
      then Some (String.sub res mlen (rlen - mlen))
      else None in
    flow.linger <- linger; mlen
  in
  match flow.linger with
  | Some res -> write_in res
  | None -> (
      match read_react flow with
      | None -> read_in ~off ~len flow buf
      | Some res -> write_in res)

let writev flow bufs =
  match flow.state with
  | `Closed | `Write_closed _ -> raise Closed_by_peer
  | `Error exn -> reraise exn
  | `Active tls | `Read_closed tls -> (
      match Tls.Engine.send_application_data tls bufs with
      | Some (tls, answer) ->
          flow.state <- inject_state tls flow.state;
          write flow answer
      | None -> assert false)

let rec drain_handshake flow =
  let push_linger flow mcs =
    match (mcs, flow.linger) with
    | None, _ -> ()
    | scs, None -> flow.linger <- scs
    | Some cs, Some l -> flow.linger <- Some (l ^ cs)
  in
  match flow.state with
  | `Active tls when not (Tls.Engine.handshake_in_progress tls) -> flow
  | (`Read_closed _ | `Closed) when garbage flow -> flow
  | _ ->
      Log.debug (fun m -> m "start to read something from the TLS session");
      let mcs = read_react flow in
      push_linger flow mcs;
      drain_handshake flow

let close flow =
  match flow.state with
  | `Active tls | `Read_closed tls ->
      let tls, str = Tls.Engine.send_close_notify tls in
      flow.rd_closed <- true;
      flow.state <- inject_state tls flow.state;
      flow.state <- `Closed;
      inhibit (write flow) str;
      Miou_unix.close flow.fd
  | `Write_closed _ ->
      flow.rd_closed <- true;
      flow.state <- `Closed;
      Miou_unix.close flow.fd
  | `Closed -> flow.rd_closed <- true
  | `Error _ ->
      flow.rd_closed <- true;
      Miou_unix.close flow.fd

let closed_by_user flow = function
  | `read | `read_write -> flow.rd_closed <- true
  | `write -> ()

let shutdown flow mode =
  closed_by_user flow mode;
  match (flow.state, mode) with
  | `Active tls, `read ->
      Log.debug (fun m -> m "shutdown `read");
      flow.state <- inject_state tls (half_close flow.state mode)
  | (`Active tls | `Read_closed tls), (`write | `read_write) ->
      let tls, str = Tls.Engine.send_close_notify tls in
      flow.state <- inject_state tls (half_close flow.state mode);
      (* NOTE(dinosaure): [write flow] can set [flow.state]. So we must
         check if the actual [flow.state] or the [flow.state] after [write flow]
         want to close the underlying file-descriptor. *)
      let to_close = flow.state = `Closed in
      inhibit (write flow) str;
      if to_close || flow.state = `Closed then Miou_unix.close flow.fd
  | `Write_closed tls, (`read | `read_write) ->
      flow.state <- inject_state tls (half_close flow.state mode);
      if flow.state = `Closed then Miou_unix.close flow.fd
  | `Error _, _ -> Miou_unix.close flow.fd
  | `Read_closed _, `read -> ()
  | `Write_closed _, `write -> ()
  | `Closed, _ -> ()

let client_of_fd conf ?(read_buffer_size = 0x1000) ?host fd =
  let conf' =
    match host with None -> conf | Some host -> Tls.Config.peer conf host
  in
  let tls, init = Tls.Engine.client conf' in
  let tls_flow =
    {
      role = `Client;
      fd;
      state = `Active tls;
      linger = None;
      read_buffer_size;
      buf = Bytes.make read_buffer_size '\000';
      rd_closed = false;
    }
  in
  write tls_flow init;
  drain_handshake tls_flow

let server_of_fd conf ?(read_buffer_size = 0x1000) fd =
  let tls = Tls.Engine.server conf in
  let tls_flow =
    {
      role = `Server;
      fd;
      state = `Active tls;
      linger = None;
      read_buffer_size;
      buf = Bytes.make read_buffer_size '\000';
      rd_closed = false;
    }
  in
  drain_handshake tls_flow

let write flow ?(off = 0) ?len str =
  let len = Option.value ~default:(String.length str - off) len in
  if off < 0 || len < 0 || off > String.length str - len
  then invalid_arg "Tls_miou.write";
  if len > 0 then writev flow [ String.sub str off len ]

let read t ?(off= 0) ?len buf =
  let len = Option.value ~default:(Bytes.length buf - off) len in
  if off < 0 || len < 0 || off > Bytes.length buf - len
  then invalid_arg "Tls_miou.read";
  if t.rd_closed then 0
  else try read_in t ~off ~len buf with End_of_file -> 0

let rec really_read_go t off len buf =
  let len' = read t buf ~off ~len in
  if len' == 0 then raise End_of_file
  else if len - len' > 0
  then really_read_go t (off + len') (len - len') buf

let really_read t ?(off= 0) ?len buf =
  let len = Option.value ~default:(Bytes.length buf - off) len in
  if off < 0 || len < 0 || off > Bytes.length buf - len
  then invalid_arg "Tls_miou.really_read";
  if len > 0 then really_read_go t off len buf

let resolve host service =
  let tcp = Unix.getprotobyname "tcp" in
  match Unix.getaddrinfo host service [ AI_PROTOCOL tcp.p_proto ] with
  | [] -> Fmt.invalid_arg "No address for %s:%s" host service
  | ai :: _ -> ai.ai_addr

let connect authenticator (v, port) =
  let conf =
    match Tls.Config.client ~authenticator () with
    | Ok config -> config
    | Error `Msg msg -> Fmt.invalid_arg "Configuration failure: %s" msg
  in
  let addr = resolve v (string_of_int port) in
  let fd =
    match addr with
    | Unix.ADDR_UNIX _ -> invalid_arg "Tls_miou.connect: Invalid UNIX socket"
    | Unix.ADDR_INET (inet_addr, _) ->
        if Unix.is_inet6_addr inet_addr then Miou_unix.tcpv6 ()
        else Miou_unix.tcpv4 ()
  in
  let host = Result.to_option Domain_name.(Result.bind (of_string v) host) in
  match Miou_unix.connect fd addr with
  | () -> client_of_fd conf ?host fd
  | exception exn ->
      Miou_unix.close fd;
      raise exn

let epoch flow = match flow.state with
  | `Active tls | `Read_closed tls | `Write_closed tls ->
    ( match Tls.Engine.epoch tls with
    | Error () -> assert false
    | Ok data -> Some data )
  | _ -> None
