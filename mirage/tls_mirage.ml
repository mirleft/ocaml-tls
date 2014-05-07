
open Mirage_sig

module TLS ( TCP : TCPV4_lwt ) = struct

  type +'a io = 'a Lwt.t
  type t      = TCP.t
  type error  = TCP.error

  type flow = {
    role           : [ `Server | `Client ] ;
    tcp            : TCP.flow ;
    mutable state  : [ `Active of Tls.Flow.state
                     | `Eof
                     | `Error of error ] ;
    mutable linger : Cstruct.t list ;
  }


  let handle_tls = function
    | `Server -> Tls.Server.handle_tls
    | `Client -> Tls.Client.handle_tls

  let error_of_alert alert =
    `Unknown (Tls.Packet.alert_type_to_string alert)

  let list_of_option = function None -> [] | Some x -> [x]


  open Lwt

  let read_react flow =

    let handle tls buf =
      match handle_tls flow.role tls buf with
      | `Ok (tls, answer, appdata) ->
          flow.state <- `Active tls ;
          TCP.write flow.tcp answer >> return (`Ok appdata)
      | `Fail (alert, answer)      ->
          let reason =
            match alert with
            | Tls.Packet.CLOSE_NOTIFY -> `Eof
            | _                       -> `Error (error_of_alert alert)
          in
          flow.state <- reason ;
          TCP.(write flow.tcp answer >> close flow.tcp) >> return reason
    in
    match flow.state with
    | `Eof | `Error _ as e -> return e
    | `Active tls          ->
        TCP.read flow.tcp >>= function
          | `Eof | `Error _ as e -> flow.state <- e ; return e
          | `Ok buf              -> handle tls buf

  let read flow =
    match flow.linger with
    | [] ->
        let rec read_more () =
          read_react flow >>= function
            | `Ok None             -> read_more ()
            | `Ok (Some buf)       -> return (`Ok buf)
            | `Eof | `Error _ as e -> return e
        in
        read_more ()
    | bufs ->
        flow.linger <- [] ;
        return (`Ok (Tls.Utils.Cs.appends @@ List.rev bufs))

  let writev flow bufs =
    match flow.state with
    | `Eof     -> fail @@ Invalid_argument "tls: write: flow is closed"
    | `Error e -> fail @@ Invalid_argument "tls: write: flow is broken"
    | `Active tls ->
        match Tls.Flow.send_application_data tls bufs with
        | Some (tls, answer) ->
            flow.state <- `Active tls ; TCP.write flow.tcp answer
        | None ->
            (* "Impossible" due to handhake draining. *)
            fail @@ Invalid_argument "tls: write: flow not ready to send"

  let write flow buf = writev flow [buf]

  let close flow =
    (* XXX Tickle the engine to produce the closing message? *)
    flow.state <- `Eof ;
    TCP.close flow.tcp

  let get_dest flow = TCP.get_dest flow.tcp

  let rec drain_handshake flow =
    match flow.state with
    | `Active tls when Tls.Flow.can_send_appdata tls -> return (`Ok flow)
    | _ ->
      read_react flow >>= function
        | `Ok mbuf ->
            flow.linger <- list_of_option mbuf @ flow.linger ;
            drain_handshake flow
        | `Error e -> return (`Error e)
        | `Eof     -> return (`Error (`Unknown "tls: end_of_file in handshake"))

  let tls_client_of_flow (cert, validator) host flow =
    let (tls, init) =
      Tls.Client.new_connection ?cert ?host ~validator () in
    let tls_flow = {
      role   = `Client ;
      tcp    = flow ;
      state  = `Active tls ;
      linger = []
    } in
    TCP.write flow init >> drain_handshake tls_flow

  let tls_server_of_flow cert flow =
    let tls_flow = {
      role   = `Server ;
      tcp    = flow ;
      state  = `Active (Tls.Server.new_connection ?cert ()) ;
      linger = []
    } in
    drain_handshake tls_flow

  let create_connection t tls_params (addr, port) =
    (* XXX addr -> (host : string) *)
    TCP.create_connection t (addr, port) >>= function
      | `Error e -> return (`Error e)
      | `Ok flow -> tls_client_of_flow tls_params None flow

end
