open Core_kernel.Std
open Async.Std

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure

(* let o f g x = f (g x) *)

type tracer = Sexplib.Sexp.t -> unit

(* module Lwt_cs = struct *)

(*   let naked ~name f fd cs = *)
(*     Cstruct.(f fd cs.buffer cs.off cs.len) >>= fun res -> *)
(*     match Lwt_unix.getsockopt_error fd with *)
(*     | None     -> return res *)
(*     | Some err -> fail @@ Unix.Unix_error (err, name, "") *)

(*   let write = naked ~name:"Tls_lwt.write" Lwt_bytes.write *)
(*   and read  = naked ~name:"Tls_lwt.read"  Lwt_bytes.read *)

(*   let rec write_full fd = function *)
(*     | cs when Cstruct.len cs = 0 -> return_unit *)
(*     | cs -> write fd cs >>= o (write_full fd) (Cstruct.shift cs) *)
(* end *)

module Unix = struct

  type t = {
    reader         : Reader.t ;
    writer         : Writer.t ;
    tracer         : tracer option ;
    mutable state  : [ `Active of Tls.Engine.state
                     | `Eof
                     | `Error of exn ] ;
    mutable linger : Cstruct.t option ;
  }

  let safely th =
    Monitor.protect (fun () -> Deferred.ignore th) ~finally:(fun () -> Deferred.unit)

  let read_t t cs =
    let bs = cs |> Cstruct.to_bigarray |> Bigsubstring.of_bigstring in
    Monitor.try_with ~extract_exn:true
      (fun () -> Reader.read_bigsubstring t.reader bs) >>| function
    | Ok res -> res
    | Error exn ->
      t.state <- `Error exn ;
      raise exn

  let write_t t (cs : Cstruct.t) =
    Cstruct.(Writer.write_bigstring t.writer cs.buffer ~pos:cs.off ~len:cs.len) ;
    Writer.flushed t.writer

  (* let (read_t, write_t) = *)
  (*   let recording_errors op t cs = *)
  (*     Lwt.catch *)
  (*       (fun () -> op t.fd cs) *)
  (*       (fun exn -> *)
  (*          t.state <- `Error exn ; *)
  (*          fail exn) *)
  (*   in *)
  (*   (recording_errors Lwt_cs.read, recording_errors Lwt_cs.write_full) *)

  let when_some f = function None -> Deferred.unit | Some x -> f x

  let tracing t f =
    match t.tracer with
    | None      -> f ()
    | Some hook -> Tls.Tracing.active ~hook f

  let recv_buf = Cstruct.create 4096

  let rec read_react t =

    let handle tls buf =
      match
        tracing t @@ fun () -> Tls.Engine.handle_tls tls buf
      with
      | `Ok (state', `Response resp, `Data data) ->
          let state' = match state' with
            | `Ok tls  -> `Active tls
            | `Eof     -> `Eof
            | `Alert a -> `Error (Tls_alert a)
          in
          t.state <- state' ;
          (resp |> when_some (write_t t)) >>= fun () -> return (`Ok data)

      | `Fail (alert, `Response resp) ->
          t.state <- `Error (Tls_failure alert) ;
          write_t t resp >>= fun () -> read_react t
    in

    match t.state with
    | `Error e  -> raise e
    | `Eof      -> return `Eof
    | `Active _ ->
        read_t t recv_buf >>= fun n ->
        match (t.state, n) with
        | `Error e, _ -> raise e
        | `Eof, _ -> return `Eof
        | (`Active _  , `Eof) -> t.state <- `Eof ; return `Eof
        | (`Active tls, `Ok n) -> handle tls (Cstruct.sub recv_buf 0 n)

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

  let writev t css =
    match t.state with
    | `Error err  -> raise err
    | `Eof        -> invalid_arg "tls: closed socket"
    | `Active tls ->
        match
          tracing t @@ fun () -> Tls.Engine.send_application_data tls css
        with
        | Some (tls, tlsdata) ->
            ( t.state <- `Active tls ; write_t t tlsdata )
        | None -> invalid_arg "tls: write: socket not ready"

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
      let open Tls.Utils.Cs in
      match (mcs, t.linger) with
      | (None, _)         -> ()
      | (scs, None)       -> t.linger <- scs
      | (Some cs, Some l) -> t.linger <- Some (l <+> cs)
    in
    match t.state with
    | `Active tls when Tls.Engine.can_handle_appdata tls ->
        return t
    | _ ->
        read_react t >>= function
          | `Eof     -> raise End_of_file
          | `Ok cs   -> push_linger t cs ; drain_handshake t

  let reneg t =
    match t.state with
    | `Error err  -> raise err
    | `Eof        -> invalid_arg "tls: closed socket"
    | `Active tls ->
        match tracing t @@ fun () -> Tls.Engine.reneg tls with
        | None -> invalid_arg "tls: can't renegotiate"
        | Some (tls', buf) ->
           t.state <- `Active tls' ;
           write_t t buf >>= fun () ->
           Deferred.ignore @@ drain_handshake t

  let close_tls t =
    match t.state with
    | `Active tls ->
        let (_, buf) = tracing t @@ fun () ->
          Tls.Engine.send_close_notify tls in
        t.state <- `Eof ;
        write_t t buf
    | _ -> Deferred.unit

  let close t =
    safely (close_tls t) >>= fun () ->
    Deferred.all_unit [Writer.close t.writer ; Reader.close t.reader]

  let set_error t exn =
    t.state <- `Error exn

  let create_server ?trace config r w =
    drain_handshake {
      state  = `Active (Tls.Engine.server config) ;
      reader = r ;
      writer = w ;
      linger = None ;
      tracer = trace ;
    } >>| fun t ->
    Monitor.detach_and_iter_errors ~f:(set_error t) @@ Writer.monitor w ;
    t

  let create_client ?trace config ?host r w =
    let config' = match host with
      | None -> config
      | Some host -> Tls.Config.peer config host
    in
    let (tls, init) = Tls.Engine.client config' in
    let t = {
      state  = `Active tls ;
      reader = r ;
      writer = w ;
      linger = None ;
      tracer = trace ;
    } in
    write_t t init >>= fun () ->
    Monitor.detach_and_iter_errors ~f:(set_error t) @@ Writer.monitor w ;
    drain_handshake t


  let accept ?trace conf r w =
    Monitor.try_with
      (fun () -> create_server conf ?trace r w) >>| function
    | Ok res -> res
    | Error err ->
      don't_wait_for @@ Reader.close r ;
      don't_wait_for @@ Writer.close w ;
      raise err

  let connect ?trace conf ~host r w =
    Monitor.try_with
      (fun () -> create_client ?trace conf ~host r w) >>| function
    | Ok res -> res
    | Error err ->
      don't_wait_for @@ Reader.close r ;
      don't_wait_for @@ Writer.close w ;
      raise err

  let read_bytes t bs off len =
    read t (Cstruct.of_bigarray ~off ~len bs)

  let write_bytes t bs off len =
    write t (Cstruct.of_bigarray ~off ~len bs)

  let epoch t =
    match t.state with
    | `Active tls -> ( match Tls.Engine.epoch tls with
        | `InitialEpoch -> assert false (* can never occur! *)
        | `Epoch data   -> `Ok data )
    | `Eof      -> `Error
    | `Error _  -> `Error
end

let of_t t =
  let buf = Bigstring.create 4096 in
  let rec read_loop t w =
    Unix.read_bytes t buf 0 4096 >>= fun len ->
    Pipe.write w @@ Bigstring.To_string.subo buf ~len >>= fun () ->
    read_loop t w
  in
  let writer = Pipe.create_writer @@ Pipe.iter ~f:(fun s ->
      Unix.write t @@ Cstruct.of_string s) in
  let reader = Pipe.create_reader ~close_on_exception:true (read_loop t) in
  Reader.of_pipe (Info.of_string "reader") reader >>= fun reader ->
  Writer.of_pipe (Info.of_string "writer") writer >>|
  fun (writer, `Closed_and_flushed_downstream _flushed) ->
  don't_wait_for (Reader.close_finished reader >>= fun () ->
                  Unix.(safely (close t))) ;
  don't_wait_for (Writer.close_finished writer >>= fun () ->
                  Unix.(safely (close t))) ;
  reader, writer

let accept_ext ?trace conf r w =
  Unix.accept ?trace conf r w >>= of_t

let connect_ext ?trace conf ~host r w =
  Unix.connect ?trace conf ~host r w >>= of_t

let accept ?trace certificate =
  let config = Tls.Config.server ~certificates:certificate ()
  in accept_ext ?trace config

let connect ?trace authenticator =
  let config = Tls.Config.client ~authenticator ()
  in connect_ext ?trace config

(* Boot the entropy loop at module init time. *)
let () = ignore @@ Nocrypto_entropy_unix.initialize ()
