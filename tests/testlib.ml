
let time f =
  let t1 = Sys.time () in
  let r  = f () in
  let t2 = Sys.time () in
  ( Printf.eprintf "[time] %f.04 s\n%!" (t2 -.  t1) ; r )

let cs_eq = Tls.Utils.cs_eq

module Flow = struct

  let rewrap_st = function (`S _, st) -> `S st | (`C _, st) -> `C st

  let unwrap_st = function `S st -> st | `C st -> st

  let can_send_appdata st =
    Tls.Flow.can_send_appdata (unwrap_st st)

  let send_application_data state data =
    match
      Tls.Flow.send_application_data (unwrap_st state) data
    with
    | None           -> None
    | Some (st', cs) -> Some (rewrap_st (state, st'), cs)

  let handle_tls ~tag state msg =
    let (handler, descr) = match state with
      | `S st -> (Tls.Server.handle_tls st, "server")
      | `C st -> (Tls.Client.handle_tls st, "client") in
    match handler msg with
    | `Fail _                 ->
        failwith @@ Printf.sprintf "[%s] error in %s" tag descr
    | `Ok (st', ans, appdata) ->
        (rewrap_st (state, st'), ans, appdata)
end

let loop_chatter ~cert ~loops ~size =

  Printf.eprintf "Looping %d times, %d bytes.\n%!" loops size;

  let message  = Nocrypto.Rng.generate size
  and server   = Tls.Server.new_connection ~cert ()
  and (client, init) =
    Tls.Client.new_connection ~validator:Tls.X509.Validator.null () in

  time @@ fun () ->

    let rec handshake srv cli cli_msg =
      let tag = "handshake" in
      let (srv, ans, _) = Flow.handle_tls ~tag srv cli_msg in
      let (cli, ans, _) = Flow.handle_tls ~tag cli ans in
      if Flow.can_send_appdata cli then (srv, cli)
      else handshake srv cli ans

    and chat srv cli data = function
      | 0 -> `Done
      | n ->
          let simplex sender recv data =
            match Flow.send_application_data sender [data] with
            | None                -> `Can't_send (sender, data)
            | Some (sender', msg) ->
                match Flow.handle_tls ~tag:"chat" recv msg with
                | (recv', _, Some data') when cs_eq data data' ->
                    `Ok (sender', recv')
                | (recv', _, Some data') ->
                    `Chinese_whispers (sender, data, recv, data')
                | (_, _, None) -> failwith "expected data"
          in
          match simplex cli srv data with
          | `Ok (cli, srv) ->
            ( match simplex srv cli data with
              | `Ok (srv, cli) -> chat srv cli data (pred n)
              | err            -> err )
          | err -> err
    in
    let (srv, cli) = handshake (`S server) (`C client) init in
    chat srv cli message loops

