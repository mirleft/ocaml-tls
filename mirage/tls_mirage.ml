
open Mirage_sig

module TLS ( TCP : TCPV4_lwt ) = struct

  type +'a io = 'a TCP.io

  type t      = TCP.t

  type error  = TCP.error

  type flow = {
    role           : [ `Server
                     | `Client ] ;
    tcp            : TCP.flow ;
    mutable state  : [ `Active of Tls.Flow.state
                     | `Eof
                     | `Error of error ] ;
    mutable linger : Cstruct.t list ;
  }

  open Lwt

  let read_react flow =
    match flow.state with
    | ( `Eof | `Error _ ) as e -> return e
    | `Active state ->
        TCP.read flow.tcp >>= function
          | ( `Eof | `Error _ ) as e ->
              flow.state <- e ; return e
          | `Ok buf ->
              match
                ( match flow.role with
                  | `Server -> Tls.Server.handle_tls
                  | `Client -> Tls.Client.handle_tls )
                state buf
              with
              | `Ok (state, answer, appdata) ->
                  flow.state <- `Active state ;
                  TCP.write flow.tcp answer >> return (`Ok appdata)
              | `Fail (alert, answer) ->
                  let reason =
                    match alert with
                    | Tls.Packet.CLOSE_NOTIFY -> `Eof
                    | _ ->
                        let repr = Tls.Packet.alert_type_to_string alert in
                        `Error (`Unknown repr) in
                  flow.state <- reason ;
                  TCP.( write flow.tcp answer >> close flow.tcp )
                  >> return reason

  let read flow =
    match flow.linger with
    | [] ->
        let rec read_more () =
          read_react flow >>= function
            | `Ok None       -> read_more ()
            | `Ok (Some buf) -> return (`Ok buf)
            | `Eof           -> return `Eof
            | `Error e       -> return (`Error e)
        in
        read_more ()
    | bufs ->
        flow.linger <- [] ;
        return (`Ok (Tls.Utils.Cs.appends @@ List.rev bufs))

  let writev flow bufs =
    match flow.state with
    | `Eof     -> fail @@ Invalid_argument "tls: flow is closed"
    | `Error e -> fail @@ Invalid_argument "tls: flow is broken"
    | `Active state ->
        match Tls.Flow.send_application_data state bufs with
        | Some (state, answer) ->
            flow.state <- `Active state ; TCP.write flow.tcp answer
        | None ->
            (* "Impossible" due to handhake draining. *)
            fail @@ Invalid_argument "tls: flow not ready to send"

  let write flow buf = writev flow [buf]

  let close flow =
    (* XXX Closing alert? *)
    flow.state <- `Eof ;
    TCP.close flow.tcp

  let get_dest flow = TCP.get_dest flow.tcp

  let rec drain_handshake flow =
    let primed =
      match flow.state with
      | `Active state -> Tls.Flow.can_send_appdata state
      | _             -> false in
    if primed then
      return (`Ok flow)
    else
      read_react flow >>= function
        | `Ok mbuf ->
          ( match mbuf with
            | None     -> ()
            | Some buf -> flow.linger <- buf :: flow.linger ) ;
            drain_handshake flow
        | `Error e -> return (`Error e)

  let tls_client_of_flow (cert, validator) host flow =
    let (state, init) =
      Tls.Client.new_connection ?cert ?host ~validator () in
    let tls_flow = {
      role   = `Client ;
      tcp    = flow ;
      state  = `Active state ;
      linger = []
    } in
    TCP.write flow init >> drain_handshake tls_flow


  let create_connection t tls_params (addr, port) =
    (* XXX addr -> (host : string) *)
    TCP.create_connection t (addr, port) >>= function
      | `Error e -> return (`Error e)
      | `Ok flow -> tls_client_of_flow tls_params None flow
end
