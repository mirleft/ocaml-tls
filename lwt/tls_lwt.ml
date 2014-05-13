
open Lwt

exception Tls_alert  of Tls.Packet.alert_type

type o_server = X509_lwt.priv
type o_client = X509_lwt.validator

type t = {
  role           : [ `Server | `Client ] ;
  fd             : Lwt_unix.file_descr ;
  mutable state  : [ `Active of Tls.Flow.state
                   | `Eof
                   | `Error of exn ] ;
  mutable linger : Cstruct.t option ;
}

let o f g x = f (g x)

module Lwt_cs = struct

  let naked ~name f fd cs =
    lwt res = Cstruct.(f fd cs.buffer cs.off cs.len) in
    match Lwt_unix.getsockopt_error fd with
    | None     -> return res
    | Some err -> fail @@ Unix.Unix_error (err, name, "")

  let write = naked ~name:"Tls_lwt.write" Lwt_bytes.write
  and read  = naked ~name:"Tls_lwt.read"  Lwt_bytes.read

  let rec write_full fd = function
    | cs when Cstruct.len cs = 0 -> return_unit
    | cs -> write fd cs >>= o (write_full fd) (Cstruct.shift cs)
end

let (read_t, write_t) =
  let finalize op t cs =
    try_lwt op t.fd cs with exn ->
      ( t.state <- `Error exn ; Lwt_unix.close t.fd >> fail exn )
  in
  ( finalize Lwt_cs.read, finalize Lwt_cs.write_full )

let safely f a =
  try_lwt ( f a >> return_unit ) with _ -> return_unit

let handle_tls = function
  | `Server -> Tls.Server.handle_tls
  | `Client -> Tls.Client.handle_tls

let recv_buf = Cstruct.create 4096

let rec read_react t =

  let handle tls buf =
    match handle_tls t.role tls buf with
    | `Ok (tls, answer, appdata) ->
        t.state <- `Active tls ;
        write_t t answer >> return (`Ok appdata)
    | `Fail (alert, answer)      ->
        t.state <-
          ( match alert with
            | Tls.Packet.CLOSE_NOTIFY -> `Eof
            | _                       -> `Error (Tls_alert alert) ) ;
        safely (Lwt_cs.write_full t.fd) answer >> Lwt_unix.close t.fd
        >> read_react t
  in

  match t.state with
  | `Error e    -> fail e
  | `Eof        -> return `Eof
  | `Active tls -> 
      read_t t recv_buf >>= function
        | 0 -> t.state <- `Eof ; return `Eof
        | n -> handle tls (Cstruct.sub recv_buf 0 n)

let rec read t buf =

  let writeout res =
    let open Cstruct in
    let rlen = len res in
    let n    = min (len buf) rlen in
    blit res 0 buf 0 n ;
    t.linger <-
      (if n < rlen then Some (sub res n (rlen - n)) else None) ;
    return n in

  match t.linger with
  | Some res -> writeout res
  | None     ->
      read_react t >>= function
        | `Eof           -> return 0
        | `Ok None       -> read t buf
        | `Ok (Some res) -> writeout res

let write t cs =
  match t.state with
  | `Error err  -> fail err
  | `Eof        -> fail @@ Invalid_argument "tls: closed socket"
  | `Active tls ->
      match Tls.Flow.send_application_data tls [cs] with
      | None -> fail @@ Invalid_argument "tls: write: socket not ready"
      | Some (tls, tlsdata) ->
          t.state <- `Active tls ;
          write_t t tlsdata >> return (Cstruct.len cs)

let push_linger t mcs =
  let open Tls.Utils.Cs in
  match (mcs, t.linger) with
  | (None, _)         -> ()
  | (scs, None)       -> t.linger <- scs
  | (Some cs, Some l) -> t.linger <- Some (l <+> cs)

let rec drain_handshake t =
  match t.state with
  | `Active tls when Tls.Flow.can_send_appdata tls ->
      return t
  | _ ->
      read_react t >>= function
        | `Eof     -> fail End_of_file
        | `Ok cs   -> push_linger t cs ; drain_handshake t

let server_of_fd cert fd =
  drain_handshake {
    role   = `Server ;
    state  = `Active (Tls.Server.new_connection ~cert ()) ;
    linger = None ;
    fd ;
  }

let client_of_fd validator ~host fd =
  let (tls, init) = Tls.Client.new_connection ~validator ~host ()
  in
  let t = {
    role   = `Client ;
    state  = `Active tls ;
    linger = None ;
    fd
  } in
  Lwt_cs.write_full fd init >> drain_handshake t


(* This really belongs just about anywhere else: generic unix name resolution. *)
let resolve host service =
  let open Lwt_unix in
  lwt tcp = getprotobyname "tcp" in
  match_lwt getaddrinfo host service [AI_PROTOCOL tcp.p_proto] with
  | []    ->
      let msg = Printf.sprintf "no address for %s:%s" host service in
      fail (Invalid_argument msg)
  | ai::_ -> return ai.ai_addr


let accept param fd =
  lwt (fd', addr) = Lwt_unix.accept fd in
  lwt t      = server_of_fd param fd' in
  return (t, addr)

let connect param (host, port) =
  lwt addr = resolve host (string_of_int port) in
  let fd   = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
  Lwt_unix.connect fd addr >> client_of_fd param ~host fd



(* let io_pair_of_fd fd =
  Lwt_io.(of_fd ~mode:Input fd, of_fd ~mode:Output fd) *)

(* let write_cs oc = function
  | cs when Cstruct.len cs = 0 -> return ()
  | cs -> Lwt_io.write oc (Cstruct.to_string cs) *)

(* let write_cs_full fd cs =
  let n = Cstruct.len cs in
  let rec write cs = function
    | 0 -> return (`Ok n)
    | n -> 
  let rec write = function
    | cs when empty cs -> return (`Ok (Cstruct.len cs)) *)

(* let network_read_and_react socket =
  lwt str = Lwt_io.read ~count:4096 socket.input in
  |+ XXX smarter treatment of hangup +|
  lwt ()  = if str = "" then fail End_of_file else return () in
  match
    Tls.Engine.handle_tls socket.state (Cstruct.of_string str)
  with
  | `Ok (state, ans, adata) ->
      socket.state <- state ;
      write_cs socket.output ans >> return adata
  | `Fail (alert, errdata) ->
      |+ XXX kill state +|
      write_cs socket.output errdata >>
      match alert with
      | Tls.Packet.CLOSE_NOTIFY -> fail End_of_file
      | _                       -> fail (Tls_alert alert) *)

(* let rec read socket =
  match socket.input_leftovers with
  | [] ->
      let rec loop () =
        match_lwt network_read_and_react socket with
        | Some data -> return data
        | None      -> loop () in
      loop ()
  | css ->
      socket.input_leftovers <- [] ;
      return @@ Tls.Utils.Cs.appends (List.rev css) *)

(* let writev socket css =
  match Tls.Flow.send_application_data socket.state css with
  | Some (state, tlsdata) ->
      socket.state <- state ;
      write_cs socket.output tlsdata
  | None -> fail @@ Invalid_argument "tls: send before handshake"

let write socket cs = writev socket [cs] *)

(* let rec drain_handshake = function
  | socket when Tls.Flow.can_send_appdata socket.state ->
      return socket
  | socket ->
      lwt res = network_read_and_react socket in
      ( match res with
        | None      -> ()
        | Some data ->
            socket.input_leftovers <- data :: socket.input_leftovers );
      drain_handshake socket

let server_of_fd ?cert fd =
  let (input, output) = io_pair_of_fd fd in
  let socket1 =
    let direction       = Server
    and state           = Tls.Engine.listen_connection ?cert ()
    and input_leftovers = [] in
    { input ; output ; direction ; state ; input_leftovers } in
  drain_handshake socket1

let client_of_fd ?cert ?host ~validator fd =
  let (input, output) = io_pair_of_fd fd in
  let (state, init) =
    Tls.Engine.open_connection ?cert ?host ~validator () in
  let socket1 =
    let direction       = Client
    and input_leftovers = [] in
    { input ; output ; direction ; state ; input_leftovers } in
  write_cs output init >> drain_handshake socket1

let accept ?cert fd =
  lwt (fd', addr) = Lwt_unix.accept fd in
  lwt socket      = server_of_fd ?cert fd' in
  return (socket, addr)

let connect ?cert ~validator ~host ~port =
  lwt addr = resolve host port in
  let fd   = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
  Lwt_unix.connect fd addr >> client_of_fd ~host ?cert ~validator fd *)
