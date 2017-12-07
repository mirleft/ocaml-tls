open Lwt

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure

let o f g x = f (g x)

type tracer = Sexplib.Sexp.t -> unit

(* This really belongs just about anywhere else: generic unix name resolution. *)
let resolve host service =
  let open Lwt_unix in
  getprotobyname "tcp" >>= fun tcp ->
  getaddrinfo host service [AI_PROTOCOL tcp.p_proto] >>= function
  | []    ->
      let msg = Printf.sprintf "no address for %s:%s" host service in
      fail (Invalid_argument msg)
  | ai::_ -> return ai.ai_addr


let gettimeofday = Unix.gettimeofday

module Lwt_cs = struct

  let naked ~name f fd cs =
    Cstruct.(f fd cs.buffer cs.off cs.len) >>= fun res ->
    match Lwt_unix.getsockopt_error fd with
    | None     -> return res
    | Some err -> fail @@ Unix.Unix_error (err, name, "")

  let write = naked ~name:"Tls_lwt.write" Lwt_bytes.write
  and read  = naked ~name:"Tls_lwt.read"  Lwt_bytes.read

  let rec write_full fd = function
    | cs when Cstruct.len cs = 0 -> return_unit
    | cs -> write fd cs >>= o (write_full fd) (Cstruct.shift cs)
end

module Unix = struct

  type t = {
    fd             : Lwt_unix.file_descr ;
    tracer         : tracer option ;
    mutable state  : [ `Active of Tls.Engine.state
                     | `Eof
                     | `Error of exn ] ;
    mutable linger : Cstruct.t option ;
  }

  let safely th =
    Lwt.catch (fun () -> th >>= fun _ -> return_unit) (fun _ -> return_unit)

  let (read_t, write_t) =
    let recording_errors op t cs =
      Lwt.catch
        (fun () -> op t.fd cs)
        (fun exn ->
           t.state <- `Error exn ;
           fail exn)
    in
    (recording_errors Lwt_cs.read, recording_errors Lwt_cs.write_full)

  let when_some f = function None -> return_unit | Some x -> f x

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
    | `Error e  -> fail e
    | `Eof      -> return `Eof
    | `Active _ ->
        read_t t recv_buf >>= fun n ->
        match (t.state, n) with
        | (`Active _  , 0) -> t.state <- `Eof ; return `Eof
        | (`Active tls, n) -> handle tls (Cstruct.sub recv_buf 0 n)

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
    | `Error err  -> fail err
    | `Eof        -> fail @@ Invalid_argument "tls: closed socket"
    | `Active tls ->
        match
          tracing t @@ fun () -> Tls.Engine.send_application_data tls css
        with
        | Some (tls, tlsdata) ->
            ( t.state <- `Active tls ; write_t t tlsdata )
        | None -> fail @@ Invalid_argument "tls: write: socket not ready"

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
          | `Eof     -> fail End_of_file
          | `Ok cs   -> push_linger t cs ; drain_handshake t

  let reneg ?authenticator t =
    match t.state with
    | `Error err  -> fail err
    | `Eof        -> fail @@ Invalid_argument "tls: closed socket"
    | `Active tls ->
        match tracing t @@ fun () -> Tls.Engine.reneg ?authenticator tls with
        | None -> fail @@ Invalid_argument "tls: can't renegotiate"
        | Some (tls', buf) ->
           t.state <- `Active tls' ;
           write_t t buf >>= fun () ->
           drain_handshake t >>= fun _ ->
           return_unit

  let close_tls t =
    match t.state with
    | `Active tls ->
        let (_, buf) = tracing t @@ fun () ->
          Tls.Engine.send_close_notify tls in
        t.state <- `Eof ;
        write_t t buf
    | _ -> return_unit

  let close t =
    safely (close_tls t) >>= fun () -> Lwt_unix.close t.fd

  let server_of_fd ?trace config fd =
    drain_handshake {
      state  = `Active (Tls.Engine.server config) ;
      fd     = fd ;
      linger = None ;
      tracer = trace ;
    }

  let client_of_fd ?trace config ?host fd =
    let config' = match host with
      | None -> config
      | Some host -> Tls.Config.peer config host
    in
    let (tls, init) = Tls.Engine.client config' in
    let t = {
      state  = `Active tls ;
      fd     = fd ;
      linger = None ;
      tracer = trace ;
    } in
    write_t t init >>= fun () ->
    drain_handshake t


  let accept ?trace conf fd =
    Lwt_unix.accept fd >>= fun (fd', addr) ->
    Lwt.catch (fun () -> server_of_fd conf ?trace fd' >|= fun t -> (t, addr))
      (fun exn -> safely (Lwt_unix.close fd') >>= fun () -> fail exn)

  let connect ?trace conf (host, port) =
    resolve host (string_of_int port) >>= fun addr ->
    let fd = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
    Lwt.catch (fun () -> Lwt_unix.connect fd addr >>= fun () -> client_of_fd ?trace conf ~host fd)
      (fun exn -> safely (Lwt_unix.close fd) >>= fun () -> fail exn)

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


type ic = Lwt_io.input_channel
type oc = Lwt_io.output_channel

let of_t ?close t =
  let close = match close with
    | None   -> (fun () -> Unix.(safely (close t)))
    | Some f -> (fun () -> Unix.safely (f ()))
  in
  (Lwt_io.make ~close ~mode:Lwt_io.Input (Unix.read_bytes t)),
  (Lwt_io.make ~close ~mode:Lwt_io.Output @@
    fun a b c -> Unix.write_bytes t a b c >>= fun () -> return c)

let accept_ext ?trace conf fd =
  Unix.accept ?trace conf fd >|= fun (t, peer) -> (of_t t, peer)

and connect_ext ?trace conf addr =
  Unix.connect ?trace conf addr >|= of_t

let accept ?trace certificate =
  let config = Tls.Config.server ~certificates:certificate ()
  in accept_ext ?trace config

and connect ?trace authenticator addr =
  let config = Tls.Config.client ~authenticator ()
  in connect_ext ?trace config addr


(* Boot the entropy loop at module init time. *)
let () = ignore @@ Nocrypto_entropy_lwt.initialize ()
