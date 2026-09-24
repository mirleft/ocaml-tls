open OUnit2

let u24 n =
  String.init 3 (fun i -> Char.chr ((n lsr ((2 - i) * 8)) land 0xff))

let client_hello_record extensions =
  let ch_payload =
    "\x03\x03" ^ String.make 32 '\x00' ^ "\x00" ^ "\x00\x02\x13\x01" ^ "\x01\x00"
    ^ "\x00\x0e" ^ String.concat "" extensions
  in
  let hs = "\x01" ^ u24 (String.length ch_payload) ^ ch_payload in
  "\x16\x03\x01"
  ^ String.init 2 (fun i -> Char.chr ((String.length hs lsr ((1 - i) * 8)) land 0xff))
  ^ hs

let duplicate_supported_versions =
  let ext = "\x00\x2b\x00\x03\x02\x03\x04" in
  client_hello_record [ ext ; ext ]

let string_of_file file =
  let ic = open_in_bin file in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () -> really_input_string ic (in_channel_length ic))

let load_server_certificate () =
  let cert = string_of_file "server.pem" and key = string_of_file "server.key" in
  match
    X509.Certificate.decode_pem_multiple cert, X509.Private_key.decode_pem key
  with
  | Ok certs, Ok key -> `Single (certs, key)
  | Error (`Msg m), _ -> invalid_arg ("can't parse certificate " ^ m)
  | _, Error (`Msg m) -> invalid_arg ("can't parse private key " ^ m)

let tests =
  [ "client hello with duplicate supported_versions extensions fails, does not raise"
    >:: fun _ ->
      let certificates = load_server_certificate () in
      let cfg = Result.get_ok (Tls.Config.server ~certificates ()) in
      let st = Tls.Engine.server cfg in
      match Tls.Engine.handle_tls st duplicate_supported_versions with
      | Error (`Fatal (`Handshake (`Message _)), _) -> ()
      | Error (f, _) ->
        assert_failure ("unexpected failure: " ^ Tls.Engine.string_of_failure f)
      | Ok _ ->
        assert_failure "accepted ClientHello with duplicate supported_versions extensions"
      | exception exn ->
        assert_failure ("exception escaped handle_tls: " ^ Printexc.to_string exn)
  ]

