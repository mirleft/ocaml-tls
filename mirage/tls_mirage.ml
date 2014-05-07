
open Mirage_sig

module type TCPV4' =
  TCPV4 with type buffer = Cstruct.t
         and type 'a io  = 'a Lwt.t

module TLS ( TCP : TCPV4' ) = struct

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


end
