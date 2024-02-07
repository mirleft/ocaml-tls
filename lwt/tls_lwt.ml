open Lwt.Infix

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure

let o f g x = f (g x)

(* This really belongs just about anywhere else: generic unix name resolution. *)
let resolve host service =
  let open Lwt_unix in
  getprotobyname "tcp" >>= fun tcp ->
  getaddrinfo host service [AI_PROTOCOL tcp.p_proto] >>= function
  | []    ->
      let msg = Printf.sprintf "no address for %s:%s" host service in
      Lwt.reraise (Invalid_argument msg)
  | ai::_ -> Lwt.return ai.ai_addr

module Lwt_cs = struct

  let naked ~name f fd cs =
    Cstruct.(f fd cs.buffer cs.off cs.len) >>= fun res ->
    match Lwt_unix.getsockopt_error fd with
    | None     -> Lwt.return res
    | Some err -> Lwt.reraise @@ Unix.Unix_error (err, name, "")

  let write = naked ~name:"Tls_lwt.write" Lwt_bytes.write
  and read  = naked ~name:"Tls_lwt.read"  Lwt_bytes.read

  let rec write_full fd = function
    | cs when Cstruct.length cs = 0 -> Lwt.return_unit
    | cs -> write fd cs >>= o (write_full fd) (Cstruct.shift cs)
end

module Unix = struct

  type t = {
    fd             : Lwt_unix.file_descr ;
    mutable state  : [ `Active of Tls.Engine.state
                     | `Read_closed of Tls.Engine.state
                     | `Write_closed of Tls.Engine.state
                     | `Closed
                     | `Error of exn ] ;
    mutable linger : Cstruct.t option ;
    recv_buf       : Cstruct.t ;
  }

  let half_close state mode =
    match state, mode with
    | `Active tls, `read -> `Read_closed tls
    | `Active tls, `write -> `Write_closed tls
    | `Active _, `read_write -> `Closed
    | `Read_closed tls, `read -> `Read_closed tls
    | `Read_closed _, (`write | `read_write) -> `Closed
    | `Write_closed tls, `write -> `Write_closed tls
    | `Write_closed _, (`read | `read_write) -> `Closed
    | (`Closed | `Error _) as e, (`read | `write | `read_write) -> e

  let inject_state tls = function
    | `Active _ -> `Active tls
    | `Read_closed _ -> `Read_closed tls
    | `Write_closed _ -> `Write_closed tls
    | (`Closed | `Error _) as e -> e

  let safely th =
    Lwt.catch
      (fun () -> th >>= fun _ -> Lwt.return_unit)
      (function
        | Out_of_memory -> raise Out_of_memory
        | _ -> Lwt.return_unit)

  let (read_t, write_t) =
    let recording_errors op t cs =
      Lwt.catch
        (fun () -> op t.fd cs)
        (function
          | Out_of_memory -> raise Out_of_memory
          | exn -> (match t.state with
              | `Error _ -> ()
              | _ -> t.state <- `Error exn) ;
            Lwt.reraise exn)
    in
    (recording_errors Lwt_cs.read, recording_errors Lwt_cs.write_full)

  let when_some f = function None -> Lwt.return_unit | Some x -> f x

  let rec read_react t =

    let handle tls buf =
      match Tls.Engine.handle_tls tls buf with
      | Ok (state', eof, `Response resp, `Data data) ->
          let state' = inject_state state' t.state in
          let state' = Option.(value ~default:state' (map (fun `Eof -> half_close state' `read) eof)) in
          t.state <- state' ;
          safely (resp |> when_some (write_t t)) >|= fun () ->
          `Ok data

      | Error (fail, `Response resp) ->
          t.state <- `Error (match fail with
            | `Alert a -> Tls_alert a
            | f -> Tls_failure f);
          write_t t resp >>= fun () -> read_react t
    in

    match t.state with
    | `Error e -> Lwt.reraise e
    | `Closed
    | `Read_closed _ -> Lwt.return `Eof
    | _ ->
        read_t t t.recv_buf >>= function
        | 0 ->
          t.state <- half_close t.state `read;
          Lwt.return `Eof
        | n ->
          match t.state with
          | `Error e -> Lwt.reraise e
          | `Active tls | `Read_closed tls | `Write_closed tls ->
            handle tls (Cstruct.sub t.recv_buf 0 n)
          | `Closed -> Lwt.return `Eof

  let rec read t buf =

    let writeout res =
      let open Cstruct in
      let rlen = length res in
      let n    = min (length buf) rlen in
      blit res 0 buf 0 n ;
      t.linger <-
        (if n < rlen then Some (sub res n (rlen - n)) else None) ;
      Lwt.return n in

    match t.linger with
    | Some res -> writeout res
    | None     ->
        read_react t >>= function
          | `Eof           -> Lwt.return 0
          | `Ok None       -> read t buf
          | `Ok (Some res) -> writeout res

  let writev t css =
    match t.state with
    | `Error err  -> Lwt.reraise err
    | `Write_closed _ | `Closed -> Lwt.reraise @@ Invalid_argument "tls: closed socket"
    | `Active tls | `Read_closed tls ->
        match Tls.Engine.send_application_data tls css with
        | Some (tls, tlsdata) ->
            ( t.state <- inject_state tls t.state ; write_t t tlsdata )
        | None -> Lwt.reraise @@ Invalid_argument "tls: write: socket not ready"

  let write t cs = writev t [cs]

  (*
   * XXX bad XXX
   * This is a point that should particularly be protected from concurrent r/w.
   * Doing this before a `t` is returned is safe; redoing it during rekeying is
   * not, as the API client already sees the `t` and can mistakenly interleave
   * writes while this is in progress.
   * *)
  let rec drain_handshake t =
    let push_linger t mcs =
      match (mcs, t.linger) with
      | (None, _)         -> ()
      | (scs, None)       -> t.linger <- scs
      | (Some cs, Some l) -> t.linger <- Some (Cstruct.append l cs)
    in
    match t.state with
    | `Active tls when not (Tls.Engine.handshake_in_progress tls) ->
        Lwt.return t
    | _ ->
        read_react t >>= function
          | `Eof     -> Lwt.reraise End_of_file
          | `Ok cs   -> push_linger t cs ; drain_handshake t

  let reneg ?authenticator ?acceptable_cas ?cert ?(drop = true) t =
    match t.state with
    | `Error err  -> Lwt.reraise err
    | `Closed | `Read_closed _ | `Write_closed _ ->
        Lwt.reraise @@ Invalid_argument "tls: closed socket"
    | `Active tls ->
        match Tls.Engine.reneg ?authenticator ?acceptable_cas ?cert tls with
        | None -> Lwt.reraise @@ Invalid_argument "tls: can't renegotiate"
        | Some (tls', buf) ->
           if drop then t.linger <- None ;
           t.state <- inject_state tls' t.state ;
           write_t t buf >>= fun () ->
           drain_handshake t >>= fun _ ->
           Lwt.return_unit

  let key_update ?request t =
    match t.state with
    | `Error err -> Lwt.reraise err
    | `Write_closed _ | `Closed -> Lwt.reraise @@ Invalid_argument "tls: closed socket"
    | `Active tls | `Read_closed tls ->
      match Tls.Engine.key_update ?request tls with
      | Error f -> Lwt.reraise @@ Invalid_argument (Format.asprintf "tls: can't update key: %a" Tls.Engine.pp_failure f)
      | Ok (tls', buf) ->
        t.state <- inject_state tls' t.state ;
        write_t t buf

  let shutdown t mode =
    (match mode with
     | `read -> Lwt.return_unit
     | `write | `read_write ->
       match t.state with
       | `Active tls | `Read_closed tls ->
         let tls', buf = Tls.Engine.send_close_notify tls in
         t.state <- inject_state tls' (half_close t.state `write) ;
         write_t t buf
       | _ -> Lwt.return_unit) >>= fun () ->
    t.state <- half_close t.state mode;
    match t.state with
    | `Closed | `Error _ -> safely (Lwt_unix.close t.fd)
    | _ -> Lwt.return_unit

  let close t = shutdown t `read_write

  let server_of_fd config fd =
    drain_handshake {
      state    = `Active (Tls.Engine.server config) ;
      fd       = fd ;
      linger   = None ;
      recv_buf = Cstruct.create 4096
    }

  let client_of_fd config ?host fd =
    let config' = match host with
      | None -> config
      | Some host -> Tls.Config.peer config host
    in
    let (tls, init) = Tls.Engine.client config' in
    let t = {
      state    = `Active tls ;
      fd       = fd ;
      linger   = None ;
      recv_buf = Cstruct.create 4096
    }
    in
    write_t t init >>= fun () ->
    drain_handshake t

  let accept conf fd =
    Lwt_unix.accept fd >>= fun (fd', addr) ->
    Lwt.catch (fun () -> server_of_fd conf fd' >|= fun t -> (t, addr))
      (function
        | Out_of_memory -> raise Out_of_memory
        | exn -> safely (Lwt_unix.close fd') >>= fun () -> Lwt.reraise exn)

  let connect conf (host, port) =
    resolve host (string_of_int port) >>= fun addr ->
    let fd = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
    Lwt.catch (fun () ->
      let host =
        Result.to_option
          (Result.bind (Domain_name.of_string host) Domain_name.host)
      in
      Lwt_unix.connect fd addr >>= fun () -> client_of_fd conf ?host fd)
      (function
        | Out_of_memory -> raise Out_of_memory
        | exn -> safely (Lwt_unix.close fd) >>= fun () -> Lwt.reraise exn)

  let read_bytes t bs off len =
    read t (Cstruct.of_bigarray ~off ~len bs)

  let write_bytes t bs off len =
    write t (Cstruct.of_bigarray ~off ~len bs)

  let epoch t =
    match t.state with
    | `Active tls | `Read_closed tls | `Write_closed tls -> Tls.Engine.epoch tls
    | `Closed | `Error _ -> Error ()
end


type ic = Lwt_io.input_channel
type oc = Lwt_io.output_channel

let of_t ?close t =
  let close = match close with
    | Some f -> (fun () -> Unix.safely (f ()))
    | None   -> (fun () ->
        (* (partially) avoid double-closes by checking if the fd has already been closed *)
        match Lwt_unix.state t.Unix.fd with
        | Lwt_unix.Closed -> Lwt.return_unit
        | Lwt_unix.Opened | Lwt_unix.Aborted _ -> Unix.(safely (close t)))
  in
  (Lwt_io.make ~close ~mode:Lwt_io.Input (Unix.read_bytes t)),
  (Lwt_io.make ~close ~mode:Lwt_io.Output @@
    fun a b c -> Unix.write_bytes t a b c >>= fun () -> Lwt.return c)

let accept_ext conf fd =
  Unix.accept conf fd >|= fun (t, peer) -> (of_t t, peer)

and connect_ext conf addr =
  Unix.connect conf addr >|= of_t

let accept certificate =
  let config = Tls.Config.server ~certificates:certificate () in
  accept_ext config

and connect authenticator addr =
  let config = Tls.Config.client ~authenticator () in
  connect_ext config addr

(* Boot the entropy loop at module init time. *)
let () = Mirage_crypto_rng_lwt.initialize (module Mirage_crypto_rng.Fortuna)

let () =
  Printexc.register_printer (function
      | Tls_alert typ ->
        Some ("TLS alert from peer: " ^ Tls.Packet.alert_type_to_string typ)
      | Tls_failure f ->
        Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None)
