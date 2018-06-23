(* Build with: ocamlbuild -use-ocamlfind -pkgs lwt,lwt.ppx,lwt.unix,tls,tls.lwt handshake_test_client.native *)
let connect host port ca_dir cipher =
  let%lwt authenticator = X509_lwt.authenticator (`Ca_dir ca_dir) in
  try%lwt
    let%lwt ic, oc =
      Tls_lwt.connect_ext
        (Tls.Config.client
           ~authenticator:authenticator
           ~ciphers:[cipher]
           ()
        )
        (host, port)
    in
    let%lwt () =
      Lwt_io.eprintf
        "%s          SUCCESS: %s\n%!"
        (if Tls.Ciphersuite.ciphersuite_tls12_only cipher then "TLS1.2 " else "       ")
        (Tls.Ciphersuite.ciphersuite_to_string cipher)
    in
    Lwt.return ()
  with
  | Tls_lwt.Tls_alert Tls.Packet.HANDSHAKE_FAILURE ->
      Lwt_io.eprintf
        "%sHANDSHAKE FAILURE: %s\n%!"
        (if Tls.Ciphersuite.ciphersuite_tls12_only cipher then "TLS1.2 " else "       ")
        (Tls.Ciphersuite.ciphersuite_to_string cipher)
  | Unix.Unix_error (e, _, _) ->
      Lwt_io.eprintf
        "UNIX ERROR: %s\n%!"
        (Unix.error_message e)
  | Tls_lwt.Tls_alert alert ->
      Lwt_io.eprintf "OTHER REMOTE FAILURE: %s\n%!"
      (Tls.Packet.alert_type_to_string alert)
  | Tls_lwt.Tls_failure fail ->
      Lwt_io.eprintf "OTHER LOCAL FAILURE: %s\n%!"
      (Tls.Engine.string_of_failure fail)

let run_test host port ca_dir cipher_suite =
  let tests =
    Lwt_list.iter_p
      (fun cipher -> connect host port ca_dir cipher)
      cipher_suite
  in
  Lwt_main.run tests

let () =
  let host = ref "" in
  let port = ref 443 in
  let ca_dir = ref "/etc/ssl/certs" in
  let ciphers = ref "default" in

  let speclist = [
    ("-port", Arg.Int (fun p -> port := p), "TCP port of remote server");
    ("-ca-dir", Arg.String (fun d -> ca_dir := d), "Directory containing CA cert files");
    ("-ciphers", Arg.String (fun c -> ciphers := c), "Cipher suite to use ('default' or 'supported')");
  ] in

  let cipher_suite =
    match !ciphers with
    | "default" -> Tls.Config.Ciphers.default
    | "supported" -> Tls.Config.Ciphers.supported
    | arg -> Printf.eprintf "ERROR: Invalid cipher suite '%s' (try 'default' or 'supported')" arg ; exit 1;
  in

  let usage = "Tests TLS handshake with remote host\nUsage: handshake_test_client HOSTNAME\nSee -help for more\n" in

  Arg.parse
    speclist
    (fun anon_arg -> host := anon_arg )
    usage;

  match !host with
  | "" -> Printf.eprintf "ERROR: No hostname given\n%s" usage; exit 1;
  | _ -> ();

  run_test !host !port !ca_dir cipher_suite
