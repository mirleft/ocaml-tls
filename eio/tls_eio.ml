module Flow = Eio.Flow

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure

module Raw = struct

  type t = {
    flow                      : Flow.two_way ;
    recv_buf                  : Cstruct.t ;
    mutex                     : Eio.Mutex.t;
    mutable tls               : Tls.Engine.state ;
    mutable linger            : Cstruct.t ;

    (* We track 'close_notify' here since Tls.Engine.state doesn't track it. 
       https://github.com/mirleft/ocaml-tls/issues/452 *)
    mutable close_notify_sent : bool ;
  }

  let write_t t cs = Flow.copy (Flow.cstruct_source [cs]) t.flow

  (* A TLS 'read' requires both reading and writing to an underlying
     flow object - t.flow; therefore we use mutex to maintain the
     integrity of 'read' from multiple fibres doing interleaving
     read/write operations on the same underlying flow object. *)
  let read_t t =
    try
      Eio.Mutex.lock t.mutex ;
      let got = Flow.single_read t.flow t.recv_buf in
      let data = Cstruct.sub t.recv_buf 0 got in
      match Tls.Engine.handle_tls t.tls data with
      | Ok ( state, `Response resp, `Data application_data ) ->
        begin match state with
          | `Ok tls ->
            t.tls <- tls ;
            Option.iter (write_t t) resp
          | `Eof ->
            (* received "close_notify" alert from peer so shutdown receving data
               from the peer socket. https://www.rfc-editor.org/rfc/rfc8446#section-6.1 *)
            Eio.Flow.shutdown t.flow `Receive ;

            (* XXX should we send a 'close_notify' response in return to 'close_notify'?
               We really shouldn't since this results in full shutdown as both sides will
               have indicated that they are not going to send data anymore. TLS 1.3 doesn't
               require it and 'close_notify' should only result in partial shutdown of write
               on the sending side and partial shutdown of receive on the receiving side. *)

            (* Set it to true since 'Tls.Engine.handle_tls t.tls data' returns 'close_notify'
               as `Response resp when it encounters `close_notify` in data. See above comment
               on why we really shouldn't do this? *)
            if not t.close_notify_sent then begin
              Option.iter (write_t t) resp ;
              t.close_notify_sent <- true ;

              (* XXX shouldn't we now close 'Send' side of flow since we are sending 
                'close_notify' message ? lwt doesn't so we don't too and the fuzz
                test fails if we do, so we don't too. But we really, really should shutdown
                'Send' side of the connection here. 

                TLS 1.3 [https://www.rfc-editor.org/rfc/rfc8446#section-6.1] is very specific
                about this behaviour.                 
                
                Discuss with @talex, @hannes what should really happend on close_notify.
                
                Uncomment line to see fuzz test failing. *)
              (* Eio.Flow.shutdown t.flow `Send ; *)
            end
          | `Alert a -> raise (Tls_alert a)
        end ;

        Eio.Mutex.unlock t.mutex ;
        application_data

      | Error (failure, `Response resp) ->
        write_t t resp ;
        raise (Tls_failure failure)
    with
    | ( End_of_file | Tls_alert _ | Tls_failure _ ) as ex ->
      Eio.Mutex.unlock t.mutex ;
      raise ex

  let rec read t flow_buf : int =
    let write_application_data data =
      let data_len = Cstruct.length data in
      let n        = min (Cstruct.length flow_buf) data_len in
      Cstruct.blit data 0 flow_buf 0 n ;
      t.linger <-
        if n < data_len
        then Cstruct.sub data n (data_len -n)
        else Cstruct.empty ;
      n in

    if not @@ Cstruct.is_empty t.linger then
      write_application_data t.linger
    else
      match read_t t with
      | Some data -> write_application_data data
      | None -> read t flow_buf

  let write t cs =
    match Tls.Engine.send_application_data t.tls [cs] with
    | Some (tls, tlsdata) ->
      t.tls <- tls ;
      write_t t tlsdata
    | None -> invalid_arg "tls: write: socket not ready"

  let rec drain_handshake t =
    if not (Tls.Engine.handshake_in_progress t.tls) then t
    else
      let application_data = read_t t in
      Option.iter (fun data ->
          t.linger <-
            if Cstruct.is_empty t.linger then data
            else Cstruct.append t.linger data
        ) application_data ;
      drain_handshake t

  let reneg ?authenticator ?acceptable_cas ?cert ?(drop = true) t =
    match Tls.Engine.reneg ?authenticator ?acceptable_cas ?cert t.tls with
    | None -> invalid_arg "tls: can't renegotiate"
    | Some (tls', buf) ->
      if drop then t.linger <- Cstruct.empty ;
      t.tls <- tls' ;
      write_t t buf ;
      ignore (drain_handshake t : t)

  let key_update ?request t =
    match Tls.Engine.key_update ?request t.tls with
    | Error _ -> invalid_arg "tls: can't update key"
    | Ok (tls', buf) ->
      t.tls <- tls' ;
      write_t t buf

  let close_tls t =
    if not t.close_notify_sent then begin
      let (tls, buf) = Tls.Engine.send_close_notify t.tls in
      write_t t buf ;
      t.tls <- tls ;
      t.close_notify_sent <- true ;
    end

  let shutdown t = function
    | `Send -> close_tls t ; Flow.shutdown t.flow `Send
    | `All -> close_tls t ; Flow.shutdown t.flow `All
    | `Receive -> Flow.shutdown t.flow `Receive

  let server_of_flow config flow =
    drain_handshake
      { tls      = Tls.Engine.server config ;
        flow     = (flow :> Flow.two_way) ;
        linger   = Cstruct.empty ;
        recv_buf = Cstruct.create 4096 ;
        mutex    = Eio.Mutex.create () ;
        close_notify_sent = false ;
      }

  let client_of_flow config ?host flow =
    let config' = match host with
      | None -> config
      | Some host -> Tls.Config.peer config host
    in
    let (tls, init) = Tls.Engine.client config' in
    let t = {
      tls ;
      flow     = (flow :> Flow.two_way) ;
      linger   = Cstruct.empty ;
      recv_buf = Cstruct.create 4096 ;
      mutex    = Eio.Mutex.create () ;
      close_notify_sent = false ;
    }
    in
    write_t t init ;
    drain_handshake t

  let epoch t =
    match Tls.Engine.epoch t.tls with
    | `InitialEpoch -> assert false (* can never occur! *)
    | `Epoch data   -> Ok data

  let copy_from t src =
    try
      while true do
        let buf = Cstruct.create 4096 in
        let got = Flow.single_read src buf in
        write t (Cstruct.sub buf 0 got)
      done
    with End_of_file -> ()
end

type t = <
  Eio.Flow.two_way;
  t : Raw.t;
>

let of_t t =
  object
    inherit Eio.Flow.two_way
    method read_into = Raw.read t
    method copy = Raw.copy_from t
    method shutdown = Raw.shutdown t
    method t = t
  end

let server_of_flow config       flow = Raw.server_of_flow config       flow |> of_t
let client_of_flow config ?host flow = Raw.client_of_flow config ?host flow |> of_t

let reneg ?authenticator ?acceptable_cas ?cert ?drop (t:t) = Raw.reneg ?authenticator ?acceptable_cas ?cert ?drop t#t
let key_update ?request (t:t) = Raw.key_update ?request t#t
let epoch (t:t) = Raw.epoch t#t

let () =
  Printexc.register_printer (function
      | Tls_alert typ ->
        Some ("TLS alert from peer: " ^ Tls.Packet.alert_type_to_string typ)
      | Tls_failure f ->
        Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None)
