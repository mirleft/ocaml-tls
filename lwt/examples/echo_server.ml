
open Lwt
open Ex_common

let serve_ssl port callback =

  let tag = "server" in

  lwt cert =
    X509_lwt.private_of_pems
      ~cert:server_cert
      ~priv_key:server_key in

  let server_s =
    let open Lwt_unix in
    let s = socket PF_INET SOCK_STREAM 0 in
    bind s (ADDR_INET (Unix.inet_addr_any, port)) ;
    listen s 10 ;
    s in

  let handle channels addr =
    async @@ fun () ->
      try_lwt
        callback channels addr >> yap ~tag "<- handler done"
      with
      | Tls_lwt.Tls_alert a ->
          yap ~tag @@ "handler: " ^ Tls.Packet.alert_type_to_string a
      | exn -> yap ~tag "handler: exception" >> fail exn
  in

  yap ~tag ("-> start @ " ^ string_of_int port)
  >>
  let rec loop () =
    lwt (channels, addr) =
      Tls_lwt.accept ~trace:eprint_sexp (`Single cert) server_s in
    yap ~tag "-> connect"
    >>
    ( handle channels addr ; loop () )
  in
  loop ()


let echo_server port =
  lwt () = Tls_lwt.rng_init () in
  serve_ssl port @@ fun (ic, oc) addr ->
    lines ic |> Lwt_stream.iter_s (fun line ->
      yap "handler" ("+ " ^ line) >> Lwt_io.write_line oc line)

let () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  Lwt_main.run (echo_server port)
