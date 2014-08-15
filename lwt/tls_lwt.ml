open Lwt

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Packet.alert_type

let o f g x = f (g x)

type tracer = Sexplib.Sexp.t -> unit

(* This really belongs just about anywhere else: generic unix name resolution. *)
let resolve host service =
  let open Lwt_unix in
  lwt tcp = getprotobyname "tcp" in
  match_lwt getaddrinfo host service [AI_PROTOCOL tcp.p_proto] with
  | []    ->
      let msg = Printf.sprintf "no address for %s:%s" host service in
      fail (Invalid_argument msg)
  | ai::_ -> return ai.ai_addr


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
    try_lwt (th >> return_unit) with _ -> return_unit

  let (read_t, write_t) =
    let recording_errors op t cs =
      try_lwt op t.fd cs with exn ->
        t.state <- `Error exn ;
        safely (Lwt_unix.close t.fd) >> fail exn
    in
    (recording_errors Lwt_cs.read, recording_errors Lwt_cs.write_full)

  let send_and_close_no_exn fd buf =
    safely (Lwt_cs.write_full fd buf >> Lwt_unix.close fd)

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
      | `Ok (`Ok tls, `Response resp, `Data data) ->
          t.state <- `Active tls ;
          write_t t resp >> return (`Ok data)

      | `Ok ((`Eof | `Alert _ as err), `Response resp, `Data data) ->
          let e_res = match err with
            | `Eof     -> `Eof
            | `Alert a -> `Error (Tls_alert a) in
          t.state <- e_res ;
          send_and_close_no_exn t.fd resp >> return (`Ok data)

      | `Fail (alert, `Response resp) ->
          t.state <- `Error (Tls_failure alert) ;
          send_and_close_no_exn t.fd resp >> read_react t
    in

    match t.state with
    | `Error e  -> fail e
    | `Eof      -> return `Eof
    | `Active _ ->
        lwt n = read_t t recv_buf in
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

  let reneg t =
    match t.state with
    | `Error err  -> fail err
    | `Eof        -> fail @@ Invalid_argument "tls: closed socket"
    | `Active tls ->
        match tracing t @@ fun () -> Tls.Engine.reneg tls with
        | None -> fail @@ Invalid_argument "tls: can't rekey: handshake in progress"
        | Some (tls', buf) -> t.state <- `Active tls' ; write_t t buf

  let close t =
    match t.state with
    | `Active tls ->
        let (_, buf) = tracing t @@ fun () ->
          Tls.Engine.send_close_notify tls in
        t.state <- `Eof ;
        send_and_close_no_exn t.fd buf
    | _ -> return_unit

  let server_of_fd ?trace config fd =
    drain_handshake {
      state  = `Active (Tls.Engine.server config) ;
      fd     = fd ;
      linger = None ;
      tracer = trace ;
    }

  let client_of_fd ?trace config ~host fd =
    let config'     = Tls.Config.peer config host in
    let (tls, init) = Tls.Engine.client config' in
    let t = {
      state  = `Active tls ;
      fd     = fd ;
      linger = None ;
      tracer = trace ;
    } in
    Lwt_cs.write_full fd init >> drain_handshake t


  let accept ?trace conf fd =
    lwt (fd', addr) = Lwt_unix.accept fd in
    lwt t = server_of_fd conf ?trace fd' in
    return (t, addr)

  let connect ?trace conf (host, port) =
    lwt addr = resolve host (string_of_int port) in
    let fd   = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
    Lwt_unix.connect fd addr >> client_of_fd ?trace conf ~host fd


  let read_bytes t bs off len =
    read t (Cstruct.of_bigarray ~off ~len bs)

  let write_bytes t bs off len =
    write t (Cstruct.of_bigarray ~off ~len bs)

end


type ic = Lwt_io.input_channel
type oc = Lwt_io.output_channel

let of_t t =
  let open Lwt_io in
  let close () = Unix.close t in
  (make ~close ~mode:Input (Unix.read_bytes t)),
  (make ~close ~mode:Output @@
    fun a b c -> Unix.write_bytes t a b c >> return c)

let accept_ext ?trace conf fd =
  Unix.accept ?trace conf fd >|= fun (t, peer) -> (of_t t, peer)

and connect_ext ?trace conf addr =
  Unix.connect ?trace conf addr >|= of_t

let accept ?trace certificate =
  let config = Tls.Config.server ~certificate ()
  in accept_ext ?trace config

and connect ?trace authenticator addr =
  let config = Tls.Config.client ~authenticator ()
  in connect_ext ?trace config addr

(*
 * XXX
 * This is wrong, revisit.
 *
 * Either Rng should be functorized out of Nocrypto and we should use
 * non-blocking system rng (/dev/urandom), or we should satisfy Fortuna's
 * assumptions and keep on reseeding the rng as we go.
 * Plus, this one-time seeding uses non-blocking randomness.
 * ....
 *)
let rng_init ?(device = "/dev/urandom") () =
  let buf = Cstruct.create 32 in
  lwt dev = Lwt_unix.(openfile device [O_RDONLY] 0) in
  Lwt_cstruct.(complete (read dev) buf) >|= fun () ->
    Nocrypto.Rng.reseed buf
