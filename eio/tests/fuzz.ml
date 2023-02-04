(* Fuzz testing for tls-eio.

   This code picks two random strings, one for the client to send and one for
   the server. It then starts a send and receive fiber for each end.

   A dispatcher fiber then sends commands to these worker fibers
   (see [action] for the possible actions).

   This is intended to check for bugs in the Eio wrapper (rather than in Tls itself).
   At the moment, it's just checking that tls-eio works when used correctly.
   Each endpoint overlaps reads with writes (but not reads with other reads or
   writes with other writes).

   Some possible future improvements:

   - It currently only checks the basic read/write/close operations.
     It should be extended to check [reneg], etc too.

   - Currently, cancelling a read operation marks the Tls flow as broken.
     We should allow resuming after a cancelled read, and test that here.

   - We should try injecting faults and make sure they're handled sensibly.

   - It would be good to get coverage reports for these tests.
     However, this requires changes to crowbar:
     https://github.com/stedolan/crowbar/issues/4#issuecomment-1310277551
     (a patched version reported 54% coverage of Tls_eio.ml) *)

open Eio.Std

let src = Logs.Src.create "fuzz" ~doc:"Fuzz tests"
module Log = (val Logs.src_log src : Logs.LOG)

module W = Eio.Buf_write

type transmit_amount = Mock_socket.transmit_amount

type op =
  | Send of int                   (* The application sends some bytes to Tls *)
  | Transmit of transmit_amount   (* The network sends some types to the peer *)
  | Recv                          (* The application tries to read some data *)
  | Shutdown_send                 (* The application shuts down the sending side *)

let label name gen =
  Crowbar.with_printer Fmt.(const string name) gen

let op =
  Crowbar.choose @@ [
    Crowbar.(map [range 4096]) (fun n -> Send n);
    Crowbar.(map [range ~min:1 4096]) (fun n -> Transmit (`Bytes n));
    label "recv" @@ Crowbar.const Recv;
    label "shutdown-send" @@ Crowbar.const Shutdown_send;
  ]

type dir = To_client | To_server

let pp_dir f = function
  | To_server -> Fmt.string f "client-to-server"
  | To_client -> Fmt.string f "server-to-client"

let dir =
  Crowbar.choose [
    label "server-to-client" @@ Crowbar.const To_client;
    label "client-to-server" @@ Crowbar.const To_server;
  ]

(* A test case is a random sequence of [action]s, followed by party shutting
   down the sending side of the connection (if it hasn't already done so) and
   the network draining any queued traffic.

   Once all fibers have finished, we check that what was sent matches the data
   that has been received.

   However, due to #452, we currently skip the check on the receiving side if
   the receiver has shut down its sending side by then. *)
   
let action =
  Crowbar.option (Crowbar.pair dir op)  (* None means yield *)

(* A [Path] is one direction (either server-to-client or client-to-server).
   The two paths can be tested mostly independently (except for shutdown at the moment). *)
module Path : sig
  type t

  val create :
    sender:(Tls_eio.t, exn) result Promise.t ->
    receiver:(Tls_eio.t, exn) result Promise.t ->
    sender_closed:bool ref ->
    receiver_closed:bool ref ->
    transmit:(transmit_amount -> unit) ->
    dir -> string -> t
  (** Create a test driver for one direction, from [sender] to [receiver].
      [transmit n] causes [n] bytes to be transferred over the mock network. *)

  val close : t -> unit
  (** [close t] causes the sender to close the socket for sending.
      Futher send operations will be ignored. *)

  val run : t -> unit
  (** Run the send and receive fibers. Returns once the receiver has read EOF. *)

  val enqueue : t -> op -> unit
  (** Send a command to the send or receive fiber (depending on [op]). *)
end = struct
  type t = {
    dir : dir;
    message : string;   (* The complete message to be transmitted over this path. *)
    (* We need to construct [t] before the handshake is done, so these are promises: *)
    sender : Tls_eio.t Promise.or_exn;
    receiver : Tls_eio.t Promise.or_exn;
    mutable sent : int; (* Bytes of [message] sent so far *)
    mutable recv : int; (* Bytes of [message] received so far *)
    send_commands : [`Send of int | `Exit] Eio.Stream.t;  (* Commands for the sending fiber *)
    recv_commands : [`Recv | `Drain] Eio.Stream.t;        (* Commands for the receiving fiber *)
    transmit : transmit_amount -> unit;
    (* FIXME: We shouldn't need to care about these, but see issue #452: *)
    sender_closed : bool ref;
    receiver_closed : bool ref;
  }

  let pp_dir f t =
    pp_dir f t.dir

  let create ~sender ~receiver ~sender_closed ~receiver_closed ~transmit dir message =
    let send_commands = Eio.Stream.create max_int in
    let recv_commands = Eio.Stream.create max_int in
    { dir; message; sender; receiver; sent = 0; recv = 0;
      send_commands; recv_commands;
      transmit; sender_closed; receiver_closed }

  let shutdown t =
    Eio.Stream.add t.send_commands `Exit

  let close t =
    shutdown t;                           (* Sender stops sending *)
    t.transmit `Drain;                    (* Network transmits everything *)
    Eio.Stream.add t.recv_commands `Drain (* Receiver reads everything *)

  let run_send_thread t =
    let sender = Promise.await_exn t.sender in
    Logs.info (fun f -> f "%a: sender ready" pp_dir t);
    let rec aux () =
      match Eio.Stream.take t.send_commands with
      | `Exit ->
        Log.info (fun f -> f "%a: shutdown send (Tls level)" pp_dir t);
        t.sender_closed := true;
        Eio.Flow.shutdown sender `Send
      | `Send len ->
        let available = String.length t.message - t.sent in
        let len = min len available in
        if len > 0 then (
          let msg = Cstruct.of_string ~off:t.sent ~len t.message in
          t.sent <- t.sent + len;
          Log.info (fun f -> f "%a: sending %S" pp_dir t (Cstruct.to_string msg));
          Eio.Flow.write sender [msg];
        );
        aux ()
    in
    aux()

  let run_recv_thread t =
    let recv = Promise.await_exn t.receiver in
    Logs.info (fun f -> f "%a: receiver ready" pp_dir t);
    try
      let drain = ref false in
      while true do
        if !drain = false then (
          begin match Eio.Stream.take t.recv_commands with
            | `Recv -> ()
            | `Drain -> drain := true
          end
        );
        let buf = Cstruct.create 4096 in
        let got = Eio.Flow.single_read recv buf in
        let received = Cstruct.to_string buf ~len:got in
        Log.info (fun f -> f "%a: received %S" pp_dir t received);
        let expected = String.sub t.message t.recv got in
        if received <> expected then
          Fmt.failwith "%a: excepted %S but got %S!" pp_dir t expected received;
        t.recv <- t.recv + got
      done
    with End_of_file ->
      if not !(t.receiver_closed) then (
        if t.recv <> t.sent then
          Fmt.failwith "%a: Sender sent %d bytes, but receiver got EOF after reading only %d"
            pp_dir t
            t.sent
            t.recv;
      );
      Log.info (fun f -> f "%a: recv thread done (got EOF)" pp_dir t)

  let run t =
    Fiber.both
      (fun () -> run_send_thread t)
      (fun () -> run_recv_thread t)

  let pp_amount f = function
    | `Bytes n -> Fmt.pf f "%d bytes" n
    | `Drain -> Fmt.string f "all bytes"

  let enqueue t = function
    | Send i->
      Log.info (fun f -> f "%a: enqueue send %d bytes of plaintext" pp_dir t i);
      Eio.Stream.add t.send_commands @@ `Send i;
    | Recv ->
      Log.info (fun f -> f "%a: enqueue read from Tls" pp_dir t);
      Eio.Stream.add t.recv_commands @@ `Recv;
    | Transmit i ->
      Log.info (fun f -> f "%a: enqueue transmit %a over network" pp_dir t pp_amount i);
      t.transmit i
    | Shutdown_send ->
      Log.info (fun f -> f "%a: enqueue shutdown send" pp_dir t);
      shutdown t
end

module Config : sig
  val client : Tls.Config.client
  val server : Tls.Config.server
end = struct
  let null_auth ?ip:_ ~host:_ _ = Ok None

  let client =
    Tls.Config.client ~authenticator:null_auth ()

  let read_file path =
    let ch = open_in_bin path in
    let len = in_channel_length ch in
    let data = really_input_string ch len in
    close_in ch;
    Cstruct.of_string data

  let server =
    let certs = Result.get_ok (X509.Certificate.decode_pem_multiple (read_file "server.pem")) in
    let pk = Result.get_ok (X509.Private_key.decode_pem (read_file "server.key")) in
    let certificates = `Single (certs, pk) in
    Tls.Config.(server ~version:(`TLS_1_0, `TLS_1_3) ~certificates ~ciphers:Ciphers.supported ())
end

let dispatch_commands ~to_server ~to_client actions =
  let rec aux = function
    | [] -> 
      Log.info (fun f -> f "dispatch_commands: done");
      Path.close to_client;
      Path.close to_server
    | None :: xs ->
      Fiber.yield (); aux xs
    | Some (dir, op) :: xs ->
      let path =
        match dir with
        | To_server-> to_server
        | To_client -> to_client
      in
      Path.enqueue path op;
      aux xs
  in
  aux actions

(* In some runs we automatically perform these actions first, which allows the handshake to complete.
   This lets the fuzz tester get to the interesting cases more quickly. *)
let quickstart_actions = [
  Some (To_server, Transmit (`Bytes 4096));
  None; (* Client sends handshake *)
  None; (* Server reads handshake *)
  Some (To_client, Transmit (`Bytes 4096));
  None; (* Server replies to handshake *)
  None; (* Client reads reply *)
  Some (To_server, Transmit (`Bytes 4096));
  None; (* Client sends final part *)
  None; (* Server receives it *)
  Some (To_client, Recv);
  Some (To_server, Recv);
]

let main client_message server_message quickstart actions =
  let actions =
    if quickstart then quickstart_actions @ actions
    else actions
  in
  Eio_mock.Backend.run @@ fun () ->
  Switch.run @@ fun sw ->
  let insecure_test_rng = Mirage_crypto_rng.create (module Test_rng) in
  Mirage_crypto_rng.set_default_generator insecure_test_rng;
  let client_socket, server_socket = Mock_socket.create_pair () in
  let server_flow = Fiber.fork_promise ~sw (fun () -> Tls_eio.server_of_flow Config.server server_socket) in
  let client_flow = Fiber.fork_promise ~sw (fun () -> Tls_eio.client_of_flow Config.client client_socket) in
  let server_closed = ref false in
  let client_closed = ref false in
  let to_server =
    Path.create
      ~sender:client_flow
      ~receiver:server_flow
      ~sender_closed:client_closed
      ~receiver_closed:server_closed
      ~transmit:client_socket#transmit
      To_server client_message in
  let to_client =
    Path.create
      ~sender:server_flow
      ~receiver:client_flow
      ~sender_closed:server_closed
      ~receiver_closed:client_closed
      ~transmit:server_socket#transmit
      To_client server_message
  in
  Fiber.all [
    (fun () -> dispatch_commands actions ~to_server ~to_client);
    (fun () -> Path.run to_server);
    (fun () -> Path.run to_client);
  ]

let () =
  Crowbar.(add_test ~name:"random ops" [bytes; bytes; bool; list action] main)
