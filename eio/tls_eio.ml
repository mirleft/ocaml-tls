open Eio.Std

module Flow = Eio.Flow

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure

type Eio.Exn.Backend.t += Tls_socket_closed
let () = Eio.Exn.Backend.register_pp (fun f -> function
    | Tls_socket_closed -> Fmt.pf f "TLS_socket_closed"; true
    | _ -> false
  )

type ty = [ `Tls | Eio.Flow.two_way_ty | Eio.Resource.close_ty ]
type t = ty r

module Raw = struct

  (* We could replace [`Eof] with [`Error End_of_file] and then use
     a regular [result] type here. *)
  type t = {
    flow           : [Flow.two_way_ty | Eio.Resource.close_ty] r;
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

  let write_t t s =
    try Flow.copy_string s t.flow
    with exn ->
      (match t.state with
       | `Error _ -> ()
       | _ -> t.state <- `Error exn) ;
      raise exn

  let try_write_t t cs =
    try write_t t cs
    with _ -> Eio.Fiber.check ()      (* Error is in [t.state] *)

  let rec read_react t =

    let handle tls buf =
      match Tls.Engine.handle_tls tls buf with
      | Ok (state', eof, `Response resp, `Data data) ->
          let state' = inject_state state' t.state in
          let state' = Option.(value ~default:state' (map (fun `Eof -> half_close state' `read) eof)) in
          t.state <- state' ;
          Option.iter (try_write_t t) resp;
          Option.map Cstruct.of_string data

      | Error (fail, `Response resp) ->
          t.state <- `Error (match fail with `Alert a -> Tls_alert a | f -> Tls_failure f) ;
          write_t t resp; read_react t
    in

    match t.state with
    | `Error e  -> raise e
    | `Closed
    | `Read_closed _ -> raise End_of_file
    | _ ->
        match Flow.single_read t.flow t.recv_buf with
          | exception End_of_file ->
            t.state <- half_close t.state `read;
            raise End_of_file
          | exception exn ->
            (match t.state with
             | `Error _ -> ()
             | _ -> t.state <- `Error exn) ;
            raise exn
          | n ->
            match t.state with
            | `Error e -> raise e
            | `Active tls | `Read_closed tls | `Write_closed tls ->
              handle tls (Cstruct.to_string t.recv_buf ~off:0 ~len:n)
            | `Closed -> raise End_of_file

  let rec single_read t buf =

    let writeout res =
      let open Cstruct in
      let rlen = length res in
      let n    = min (length buf) rlen in
      blit res 0 buf 0 n ;
      t.linger <-
        (if n < rlen then Some (sub res n (rlen - n)) else None) ;
      n in

    match t.linger with
    | Some res -> writeout res
    | None     ->
        match read_react t with
          | None     -> single_read t buf
          | Some res -> writeout res

  let writev t css =
    match t.state with
    | `Error err  -> raise err
    | `Write_closed _ | `Closed -> raise (Eio.Net.err (Connection_reset Tls_socket_closed))
    | `Active tls | `Read_closed tls ->
        let css = List.map Cstruct.to_string css in
        match Tls.Engine.send_application_data tls css with
        | Some (tls, tlsdata) ->
            ( t.state <- inject_state tls t.state ; write_t t tlsdata )
        | None -> invalid_arg "tls: write: socket not ready"

  let single_write t bufs =
    writev t bufs;
    Cstruct.lenv bufs

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
        t
    | _ ->
        let cs = read_react t in
        push_linger t cs; drain_handshake t

  let reneg ?authenticator ?acceptable_cas ?cert ?(drop = true) t =
    match t.state with
    | `Error err  -> raise err
    | `Closed | `Read_closed _ | `Write_closed _ -> invalid_arg "tls: closed socket"
    | `Active tls ->
        match Tls.Engine.reneg ?authenticator ?acceptable_cas ?cert tls with
        | None -> invalid_arg "tls: can't renegotiate"
        | Some (tls', buf) ->
           if drop then t.linger <- None ;
           t.state <- inject_state tls' t.state ;
           write_t t buf;
           ignore (drain_handshake t : t)

  let key_update ?request t =
    match t.state with
    | `Error err  -> raise err
    | `Write_closed _ | `Closed -> invalid_arg "tls: closed socket"
    | `Active tls | `Read_closed tls ->
      match Tls.Engine.key_update ?request tls with
      | Error f -> Fmt.invalid_arg "tls: can't update key: %a" Tls.Engine.pp_failure f
      | Ok (tls', buf) ->
        t.state <- inject_state tls' t.state ;
        write_t t buf

  let shutdown t = function
    | `Receive -> ()
    | `Send | `All ->
      match t.state with
      | `Active tls | `Read_closed tls ->
        let tls', buf = Tls.Engine.send_close_notify tls in
        t.state <- inject_state tls' (half_close t.state `write) ;
        write_t t buf
      | _ -> ()

  let server_of_flow config flow =
    drain_handshake {
      state    = `Active (Tls.Engine.server config) ;
      flow     = (flow :> [Flow.two_way_ty | Eio.Resource.close_ty] r) ;
      linger   = None ;
      recv_buf = Cstruct.create 4096
    }

  let client_of_flow config ?host flow =
    let config' = match host with
      | None -> config
      | Some host -> Tls.Config.peer config host
    in
    let (tls, init) = Tls.Engine.client config' in
    let t = {
      state    = `Active tls ;
      flow     = (flow :> [Flow.two_way_ty | Eio.Resource.close_ty] r);
      linger   = None ;
      recv_buf = Cstruct.create 4096
    } in
    write_t t init;
    drain_handshake t


  let epoch t =
    match t.state with
    | `Active tls | `Read_closed tls | `Write_closed tls -> Tls.Engine.epoch tls
    | `Closed | `Error _ -> Error ()

  let copy t ~src = Eio.Flow.Pi.simple_copy ~single_write t ~src

  let read_methods = []

  let close t = Eio.Resource.close t.flow

  type (_, _, _) Eio.Resource.pi += T : ('t, 't -> t, ty) Eio.Resource.pi
end

let raw (Eio.Resource.T (t, ops)) = Eio.Resource.get ops Raw.T t

let handler =
  Eio.Resource.handler [
    H (Eio.Flow.Pi.Source, (module Raw));
    H (Eio.Flow.Pi.Sink, (module Raw));
    H (Eio.Flow.Pi.Shutdown, (module Raw));
    H (Eio.Resource.Close, Raw.close);
    H (Raw.T, Fun.id);
  ]

let of_t t = Eio.Resource.T (t, handler)

let server_of_flow config       flow = Raw.server_of_flow config       flow |> of_t
let client_of_flow config ?host flow = Raw.client_of_flow config ?host flow |> of_t

let reneg ?authenticator ?acceptable_cas ?cert ?drop (t:t) = Raw.reneg ?authenticator ?acceptable_cas ?cert ?drop (raw t)
let key_update ?request (t:t) = Raw.key_update ?request (raw t)
let epoch (t:t) = Raw.epoch (raw t)

let () =
  Printexc.register_printer (function
      | Tls_alert typ ->
        Some ("TLS alert from peer: " ^ Tls.Packet.alert_type_to_string typ)
      | Tls_failure f ->
        Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None)
