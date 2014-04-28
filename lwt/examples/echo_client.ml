
open Ex_common
open Lwt

let echo_client host port =
  lwt validator = X509_lwt.validator (`No_validation_I'M_STUPID) in
  lwt sock      = Tls_lwt.connect validator host port
  in
  let rec network () =
    tls_read sock >>= Lwt_io.printf "[recv] %s\n%!" >> network ()
  and keyboard () =
    Lwt_io.(read_line stdin) >>= tls_write sock >> keyboard ()
  in
  Lwt.join [ network () ; keyboard () ]

let () =
  match Sys.argv with
  | [| _ ; host ; port |] -> Lwt_main.run (echo_client host port)
  | [| _ ; host |]        -> Lwt_main.run (echo_client host "443")
  | args                  -> Printf.eprintf "%s <host> <port>\n%!" args.(0)

