open Lwt
open Ex_common

let string_of_unix_err err f p =
  Printf.sprintf "Unix_error (%s, %s, %s)"
    (Unix.error_message err) f p


module HT = Hashtbl.Make (Tls.Core.PreSharedKeyID)
let cache_psk, psk_cache =
  let cache = HT.create 7 in
  ((fun ed -> HT.add cache ed.Tls.Core.psk_id ed),
   (fun id -> if HT.mem cache id then Some (HT.find cache id) else None))

let serve_ssl port callback =

  let tag = "server" in

  X509_lwt.private_of_pems
    ~cert:server_cert
    ~priv_key:server_key >>= fun cert ->

  let epoch =
    let hex = Nocrypto.Uncommon.Cs.of_hex in
    {
      Tls.Core.protocol_version = Tls.Core.TLS_1_3 ;
      ciphersuite = `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 ;
      peer_random = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
      peer_certificate = None ;
      peer_certificate_chain = [] ;
      peer_name = None ;
      trust_anchor = None ;
      received_certificates = [] ;
      own_random = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
      own_certificate = fst cert ;
      own_private_key = Some (snd cert) ;
      own_name = Some "tls13test.nqsb.io" ;
      master_secret = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
      session_id = Cstruct.create 0 ;
      extended_ms = true ;
      resumption_secret = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ;
      psk_id = hex "0000"
    }
  in
  cache_psk epoch ;

  let server_s () =
    let open Lwt_unix in
    let s = socket PF_INET SOCK_STREAM 0 in
    setsockopt s SO_REUSEADDR true ;
    bind s (ADDR_INET (Unix.inet_addr_any, port)) ;
    listen s 10 ;
    s in

  let handle channels =
    async @@ fun () ->
      Lwt.catch (fun () -> callback channels >>= fun () -> yap ~tag "<- handler done")
        (function
          | Tls_lwt.Tls_alert a ->
            yap ~tag @@ "handler: " ^ Tls.Packet.alert_type_to_string a
          | Tls_lwt.Tls_failure a ->
            yap ~tag @@ "handler: " ^ Tls.Engine.string_of_failure a
          | Unix.Unix_error (e, f, p) ->
            yap ~tag @@ "handler: " ^ (string_of_unix_err e f p)
          | exn -> yap ~tag "handler: exception")
  in

  yap ~tag ("-> start @ " ^ string_of_int port) >>= fun () ->
  let rec loop s =
    X509_lwt.authenticator `No_authentication_I'M_STUPID >>= fun authenticator ->
    let config = Tls.Config.server ~certificates:(`Single cert) ~psk_cache ~authenticator () in
    (Lwt.catch
       (fun () ->
          Lwt_unix.accept s >>= fun (s, addr) ->
          let txt = Unix.(match addr with
              | ADDR_UNIX x -> "unix-" ^ x
              | ADDR_INET (ip, p) -> string_of_inet_addr ip ^ ":" ^ string_of_int p)
          in
          yap ~tag:"client-connect" txt >>= fun () ->
          Tls_lwt.Unix.server_of_fd ~trace:eprint_sexp config s >|= fun t -> `R t)
       (function
         | Unix.Unix_error (e, f, p) -> return (`L (string_of_unix_err e f p))
         | Tls_lwt.Tls_alert a -> return (`L (Tls.Packet.alert_type_to_string a))
         | Tls_lwt.Tls_failure f -> return (`L (Tls.Engine.string_of_failure f))
         | exn -> let str = Printexc.to_string exn in return (`L ("loop: exception " ^ str)))) >>= function
    | `R t ->
       yap ~tag "-> connect" >>= fun () ->
       ((match Tls_lwt.Unix.epoch t with
         | `Ok ed -> cache_psk ed
         | `Error -> ()) ;
        handle (Tls_lwt.of_t t); loop s)
    | `L msg ->
        yap ~tag ("server socket: " ^ msg) >>= fun () -> loop s
    in
    loop (server_s ())

let echo_server port =
  serve_ssl port @@ fun (ic, oc) ->
    lines ic |> Lwt_stream.iter_s (fun line ->
      yap ~tag:"handler" ("+ " ^ string_of_int (String.length line)) >>= fun () ->
      Lwt_io.write_line oc line)

let () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  Lwt_main.run (echo_server port)
