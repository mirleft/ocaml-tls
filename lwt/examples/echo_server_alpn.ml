
open Lwt
open Ex_common

let split_on_char sep s =
  let r = ref [] in
  let j = ref (String.length s) in
  for i = String.length s - 1 downto 0 do
    if s.[i] = sep then begin
      r := String.sub s (i + 1) (!j - i - 1) :: !r;
      j := i
    end
  done;
  String.sub s 0 !j :: !r

let serve_ssl ?protocols port callback =

  let tag = "server" in

  let protostring =
    (match protocols with
     | None -> "h2,http/1.1"
     | Some protocols -> protocols)
  in
  let protos = split_on_char ',' protostring in

  X509_lwt.private_of_pems
    ~cert:server_cert
    ~priv_key:server_key >>= fun certificate ->

  let server_s =
    let open Lwt_unix in
    let s = socket PF_INET SOCK_STREAM 0 in
    bind s (ADDR_INET (Unix.inet_addr_any, port)) ;
    listen s 10 ;
    s in

  let handle ep channels addr =
    let host = match ep with
      | `Ok data -> ( match data.Tls.Core.own_name with
          | Some n -> n
          | None   -> "no name" )
      | `Error   -> "no session"
    in
    async @@ fun () ->
    Lwt.catch (fun () -> callback host channels addr >>= fun () -> yap ~tag "<- handler done")
      (function
        | Tls_lwt.Tls_alert a ->
          yap ~tag @@ "handler: " ^ Tls.Packet.alert_type_to_string a
        | exn -> yap ~tag "handler: exception" >>= fun () -> fail exn)
  in

  let ps = string_of_int port in
  yap ~tag ("-> start @ " ^ ps ^ " (use `openssl s_client -connect host:" ^ ps ^ " -alpn <proto>`), available protocols: " ^ protostring) >>= fun () ->
  let rec loop () =
    let config = Tls.Config.server ~certificates:(`Single certificate) ~alpn_protocols:protos () in
    Tls_lwt.Unix.accept ~trace:eprint_sexp config server_s >>= fun (t, addr) ->
    yap ~tag "-> connect" >>= fun () ->
    ( handle (Tls_lwt.Unix.epoch t) (Tls_lwt.of_t t) addr ; loop () )
  in
  loop ()


let echo_server ~protocols port =
  serve_ssl ?protocols port @@ fun host (ic, oc) addr ->
    lines ic |> Lwt_stream.iter_s (fun line ->
      yap ("handler " ^ host) ("+ " ^ line) >>= fun () ->
      Lwt_io.write_line oc line)

let () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  let protocols =
    try Some (Sys.argv.(1)) with _ -> None
  in
  Lwt_main.run (echo_server ~protocols port)
