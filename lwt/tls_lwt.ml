
open Lwt

exception Tls_alert  of Tls.Packet.alert_type

type socket = {
  role           : [ `Server | `Client ] ;
  fd             : Lwt_unix.file_descr ;
  mutable state  : [ `Active of Tls.Flow.state
                   | `Eof
                   | `Error of exn ] ;
  mutable linger : Cstruct.t option ;
}

type o_server = X509_lwt.priv
type o_client = X509_lwt.validator

let get_fd { fd; _ } = fd


(* type direction = Server | Client

type socket = {
  input     : Lwt_io.input_channel  ;
  output    : Lwt_io.output_channel ;
  direction : direction ;
  mutable state : Tls.Engine.state ;
  mutable input_leftovers : Cstruct.t list
} *)

(* This really belongs just about anywhere else: generic unix name resolution. *)
let resolve host service =
  let open Lwt_unix in
  lwt tcp = getprotobyname "tcp" in
  match_lwt getaddrinfo host service [AI_PROTOCOL tcp.p_proto] with
  | []    ->
      let msg = Printf.sprintf "no address for %s:%s" host service in
      fail (Invalid_argument msg)
  | ai::_ -> return ai.ai_addr


(* let io_pair_of_fd fd =
  Lwt_io.(of_fd ~mode:Input fd, of_fd ~mode:Output fd) *)

(* let write_cs oc = function
  | cs when Cstruct.len cs = 0 -> return ()
  | cs -> Lwt_io.write oc (Cstruct.to_string cs) *)


let naked_socket_op ~name f fd cs =
  try_lwt
    f fd cs.Cstruct.buffer cs.Cstruct.off cs.Cstruct.len >|= fun res ->
    match Lwt_unix.getsockopt_error fd with
    | None     -> `Ok res
    | Some err -> `Error (Unix.Unix_error (err, name, ""))
  with err -> return @@ `Error err

let write_cs = naked_socket_op ~name:"Tls_lwt.write" Lwt_bytes.write
and read_cs  = naked_socket_op ~name:"Tls_lwt.read"  Lwt_bytes.read

let rec write_cs_full fd = function
  | cs when Cstruct.len cs = 0 -> return (`Ok ())
  | cs ->
      Printf.printf "+++ will write. (%d)\n%!" (Cstruct.len cs); Cstruct.hexdump cs ;
      write_cs fd cs >>= function
        | `Error _ as e -> return e
        | `Ok n         ->
            Printf.printf "+++ wrote %d bytes.\n%!" n ;
            write_cs_full fd (Cstruct.shift cs n)


let handle_tls = function
  | `Server -> Tls.Server.handle_tls
  | `Client -> Tls.Client.handle_tls


let recv_buf = Cstruct.create 4096

let return_empty_o = return @@ Some (Cstruct.create 0)

let rec read_react socket =

  Printf.printf "**** read_react.\n%!";

  let handle tls buf =
    Printf.printf "**** handling input....\n%!" ;
    match handle_tls socket.role tls buf with
    | `Ok (tls, answer, appdata) ->
        Printf.printf "**** processed: ok (to answer: %d)\n%!" (Cstruct.len answer);
        socket.state <- `Active tls ;
        Printf.printf "**** + answer: \n%!" ; Cstruct.hexdump answer ;
        write_cs_full socket.fd answer >> return (`Ok appdata)
    | `Fail (alert, answer)      ->
        Printf.printf "**** processed: fail (to ans: %d)\n%!" (Cstruct.len answer);
        socket.state <-
          ( match alert with
            | Tls.Packet.CLOSE_NOTIFY ->
                Printf.printf "**** r/r -> eof\n%!" ; `Eof
            | _                       ->
                Printf.printf "**** r/r -> alert\n%!" ; `Error (Tls_alert alert) ) ;
        write_cs_full socket.fd answer
        >> Lwt_unix.close socket.fd
        >> read_react socket
  in
  match socket.state with
  | `Eof | `Error _ as e ->
      Printf.printf "**** rr: failed socket\n%!" ; return e
  | `Active tls ->
      Printf.printf "**** will pull from socket.\n%!" ;
      read_cs socket.fd recv_buf >>= function
        | `Ok 0 -> socket.state <- `Eof ; return `Eof
        | `Ok n -> handle tls (Cstruct.sub recv_buf 0 n)
        | `Error _ as e -> return e


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

let rec read socket buf =
  let open Cstruct in

  let emit res =
    let rlen   = len res in
    let n      = min (len buf) rlen in
    blit res 0 buf 0 n ;
    socket.linger <-
      ( if n < rlen then Some (sub res n (rlen - n)) else None ) ;
    Printf.printf "emit: res: %d linger: %d\n%!" n
      (match socket.linger with None -> 0 | Some cs -> Cstruct.len cs);
    return n
  in
  match socket.linger with
  | Some res ->
      Printf.printf "read: have linger.\n%!" ;
      Cstruct.hexdump res ;
      emit res
  | None     ->
      Printf.printf "read: will read_react.\n%!" ;
      read_react socket >>= function
        | `Eof     -> socket.state <- `Eof ; return 0
        | `Error e -> socket.state <- `Error e ; fail e
        | `Ok None -> read socket buf
        | `Ok (Some res) ->
            Printf.printf "read: got res.\n%!" ;
            emit res

let write socket cs =
  match socket.state with
  | `Eof       -> fail @@ Invalid_argument "tls: closed socket"
  | `Error err -> fail err
  | `Active state ->
      match Tls.Flow.send_application_data state [cs] with
      | None -> fail @@ Invalid_argument "tls: write: socket not ready"
      | Some (state, tlsdata) ->
          socket.state <- `Active state ;
          write_cs_full socket.fd tlsdata >>= function
            | `Error e -> fail e
            | `Ok _    -> return (Cstruct.len cs)

let push_linger socket mcs =
  match (mcs, socket.linger) with
  | (None, _)         -> ()
  | (scs, None)       -> socket.linger <- scs
  | (Some cs, Some l) -> socket.linger <- Some (Tls.Utils.Cs.(l <+> cs))

let rec drain_handshake socket =
  match socket.state with
  | `Active state when Tls.Flow.can_send_appdata state ->
      return socket
  | _ ->
      Printf.printf "**** drain hs\n%!";
      read_react socket >>= function
        | `Error e -> fail e
        | `Eof     -> fail End_of_file
        | `Ok cs   -> push_linger socket cs ; drain_handshake socket

let server_of_fd cert fd =
  let state  = Tls.Server.new_connection ~cert () in
  let socket = {
    role = `Server ; fd ; state = `Active state ; linger = None
  } in
  drain_handshake socket

let client_of_fd validator ~host fd =
  let (state, init) =
    Tls.Client.new_connection ~validator ~host () in
  let socket = {
    role = `Client ; fd ; state = `Active state ; linger = None
  } in
  write_cs_full fd init >> drain_handshake socket


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

let accept param fd =
  lwt (fd', addr) = Lwt_unix.accept fd in
  lwt socket      = server_of_fd param fd' in
  return (socket, addr)

let connect param (host, port) =
  lwt addr = resolve host (string_of_int port) in
  let fd   = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
  Lwt_unix.connect fd addr >> client_of_fd param ~host fd
