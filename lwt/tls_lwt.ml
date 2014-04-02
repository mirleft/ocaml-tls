
open Lwt

exception Tls_alert of Tls.Packet.alert_type

type direction = Server | Client

type socket = {
  input     : Lwt_io.input_channel  ;
  output    : Lwt_io.output_channel ;
  direction : direction ;
  mutable state : Tls.Flow.state ;
  mutable input_leftovers : Cstruct.t list
}

(* This really belongs just about anywhere else. *)
let resolve host service =
  let open Lwt_unix in
  lwt tcp = getprotobyname "tcp" in
  match_lwt getaddrinfo host service [AI_PROTOCOL tcp.p_proto] with
  | []    -> fail (Invalid_argument "can't resolve host")
  | ai::_ -> return ai.ai_addr


let io_pair_of_fd fd =
  Lwt_io.(of_fd ~mode:Input fd, of_fd ~mode:Output fd)

let write_cs oc = function
  | cs when Cstruct.len cs = 0 -> return ()
  | cs -> Lwt_io.write oc (Cstruct.to_string cs)

let network_read_and_react socket =
  Printf.printf "+ net read...\n%!";
  lwt str = Lwt_io.read ~count:4096 socket.input in
  (* XXX smarter treatment of hangup *)
  lwt ()  = if str = "" then fail End_of_file else return () in
  Cstruct.(hexdump @@ of_string str);
  match
    ( match socket.direction with
      | Server -> Tls.Server.handle_tls
      | Client -> Tls.Client.handle_tls )
    socket.state
    (Cstruct.of_string str)
  with
  | `Ok (state, ans, adata) ->
      Printf.printf "* engine OK\n%!";
      socket.state <- state ;
      write_cs socket.output ans >>
      return adata
  | `Fail (alert, errdata) ->
      (* XXX kill state *)
      Printf.printf "* engine Fail\n%!";
      write_cs socket.output errdata >>
      match alert with
      | Tls.Packet.CLOSE_NOTIFY -> fail End_of_file
      | _                       -> fail (Tls_alert alert)

let rec read socket =
  match socket.input_leftovers with
  | [] ->
      let rec loop () =
        Printf.printf "+ read: doing net read.\n%!";
        match_lwt network_read_and_react socket with
        | Some data -> return data
        | None      -> loop () in
      loop ()
  | css ->
      Printf.printf "+ read: static read.\n%!";
      socket.input_leftovers <- [] ;
      return @@ Tls.Utils.cs_appends (List.rev css)

let writev socket css =
  match Tls.Flow.send_application_data socket.state css with
  | Some (state, tlsdata) ->
      socket.state <- state ;
      write_cs socket.output tlsdata
  | None -> fail @@ Invalid_argument "tls: send before handshake"

let write socket cs = writev socket [cs]

let rec drain_handshake = function
  | socket when Tls.Flow.can_send_appdata socket.state ->
      return socket
  | socket ->
      Printf.printf "+ drain hs: will net read.\n%!";
      lwt res = network_read_and_react socket in
      ( match res with
        | None      -> ()
        | Some data ->
            socket.input_leftovers <- data :: socket.input_leftovers );
      drain_handshake socket

let server_of_fd fd =
  let (input, output) = io_pair_of_fd fd in
  let socket1 =
    { state           = Tls.Flow.empty_state ;
      direction       = Server ;
      input_leftovers = [] ;
      input ; output }
  in
  drain_handshake socket1

let client_of_fd ?servername fd =
  let (input, output) = io_pair_of_fd fd in
  let (state, init) = Tls.Client.new_connection servername in
  let socket1 =
    let direction       = Client
    and input_leftovers = [] in
    { input ; output ; direction ; state ; input_leftovers } in
  write_cs output init >> drain_handshake socket1

let accept fd =
  lwt (fd', addr) = Lwt_unix.accept fd in
  lwt socket      = server_of_fd fd' in
  return (socket, addr)

let connect ?fd addr =
  let fd = match fd with
    | None    -> Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0)
    | Some fd -> fd in
  Lwt_unix.connect fd addr >> client_of_fd fd

(* type event =
  | EOF
  | Error
  | Data of Cstruct.t

let install_handler socket handler =
  let rec loop () =
    lwt data = read socket in
    handler socket (Data data) >> loop () in
  ignore @@ loop () *)

