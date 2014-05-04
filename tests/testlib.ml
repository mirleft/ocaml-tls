
let time f =
  let t1 = Sys.time () in
  let r  = f () in
  let t2 = Sys.time () in
  ( Printf.eprintf "[time] %f.04 s\n%!" (t2 -.  t1) ; r )

module Flow = struct

  let rewrap_st = function (`S _, st) -> `S st | (`C _, st) -> `C st

  let unwrap_st = function `S st -> st | `C st -> st

  let can_send_appdata st =
    Tls.Flow.can_send_appdata (unwrap_st st)

  let send_application_data state data =
    match Tls.Flow.send_application_data (unwrap_st state) data with
    | None           -> None
    | Some (st', cs) -> Some (rewrap_st (state, st'), cs)

  let handle_tls ~tag state msg =
    let (handler, descr) = match state with
      | `S st -> (Tls.Server.handle_tls st, "server")
      | `C st -> (Tls.Client.handle_tls st, "client") in
    match handler msg with
    | `Fail _                 ->
        failwith @@ Printf.sprintf "[%s] error in %s" tag descr
    | `Ok (st', ans, appdata) -> (rewrap_st (state, st'), ans, appdata)
end

let loop_chatter ~cert ~loops ~size =

  Printf.eprintf "Looping %d times, %d bytes.\n%!" loops size;

  let message  = Nocrypto.Rng.generate size
  and server   = Tls.Server.new_connection ~cert ()
  and (client, init) =
    Tls.Client.new_connection ~validator:Tls.X509.Validator.null ()
  in
  time @@ fun () ->

    let rec handshake srv cli cli_msg =
      let tag = "handshake" in
      let (srv, ans, _) = Flow.handle_tls ~tag srv cli_msg in
      let (cli, ans, _) = Flow.handle_tls ~tag cli ans in
      if Flow.can_send_appdata cli then (srv, cli)
      else handshake srv cli ans

    and chat srv cli data = function
      | 0 -> data
      | n ->
          let tag = "chat" in
          let simplex sender recv data =
            match Flow.send_application_data sender [data] with
            | None                -> failwith @@ "can't send"
            | Some (sender', msg) ->
                match Flow.handle_tls ~tag recv msg with
                | (recv', _, Some data') -> (sender', recv', data')
                | (_, _, None)           -> failwith "expected data"
          in
          let (cli, srv, data1) = simplex cli srv data in
          let (srv, cli, data2) = simplex srv cli data1 in
          chat srv cli data2 (pred n)
    in
    let (srv, cli) = handshake (`S server) (`C client) init in
    let message' = chat srv cli message loops in
    if Tls.Utils.Cs.equal message message' then ()
    else failwith @@ "the message got corrupted :("

