
open Lwt

exception Tls_alert  of Tls.Packet.alert_type

type o_server = X509_lwt.priv
type o_client = X509_lwt.validator

let o f g x = f (g x)

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
    role           : [ `Server | `Client ] ;
    fd             : Lwt_unix.file_descr ;
    mutable state  : [ `Active of Tls.Flow.state
                     | `Eof
                     | `Error of exn ] ;
    mutable linger : Cstruct.t option ;
  }

  let close t =
    (* XXX send close alert *)
    match t.state with
    | `Active _ -> t.state <- `Eof ; Lwt_unix.close t.fd
    | _         -> return_unit

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
      | `Fail (alert, answer) ->
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

  let writev t css =
    match t.state with
    | `Error err  -> fail err
    | `Eof        -> fail @@ Invalid_argument "tls: closed socket"
    | `Active tls ->
        match Tls.Flow.send_application_data tls css with
        | Some (tls, tlsdata) ->
            ( t.state <- `Active tls ; write_t t tlsdata )
        | None -> fail @@ Invalid_argument "tls: write: socket not ready"

  let write t cs = writev t [cs]

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
      fd     = fd ;
      linger = None ;
    }

  let client_of_fd validator ~host fd =
    let (tls, init) = Tls.Client.new_connection ~validator ~host ()
    in
    let t = {
      role   = `Client ;
      state  = `Active tls ;
      fd     = fd ;
      linger = None ;
    } in
    Lwt_cs.write_full fd init >> drain_handshake t


  let accept param fd =
    lwt (fd', addr) = Lwt_unix.accept fd in
    lwt t = server_of_fd param fd' in
    return (t, addr)

  let connect param (host, port) =
    lwt addr = resolve host (string_of_int port) in
    let fd   = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
    Lwt_unix.connect fd addr >> client_of_fd param ~host fd


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

let accept param fd =
  Unix.accept param fd >|= fun (t, peer) -> (of_t t, peer)

and connect param addr = Unix.connect param addr >|= of_t

