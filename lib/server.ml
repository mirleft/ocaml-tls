open Core
open Flow
open Flow.Or_alert

open Nocrypto

(* server configuration *)
type server_config = {
  key_file         : string ;
  certificate_file : string
}

let default_server_config = {
  key_file         = "server.key" ;
  certificate_file = "server.pem"
}

let answer_client_finished (sp : security_parameters) (packets : Cstruct.t list) (fin : Cstruct.t) (raw : Cstruct.t)  =
  let computed = Crypto.finished sp.master_secret "client finished" packets in
  fail_neq computed fin Packet.HANDSHAKE_FAILURE >>= fun () ->
  let my_checksum = Crypto.finished sp.master_secret "server finished" (packets @ [raw]) in
  let fin = Writer.assemble_handshake (Finished my_checksum) in
  let params = { sp with client_verify_data = computed ;
                         server_verify_data = my_checksum }
  in
  print_security_parameters params;
  return (`Established params, [`Record (Packet.HANDSHAKE, fin)], `Pass)

let answer_client_key_exchange (sp : security_parameters) (packets : Cstruct.t list) (kex : Cstruct.t) (raw : Cstruct.t) =
  ( match Ciphersuite.ciphersuite_kex sp.ciphersuite with

    | Ciphersuite.RSA ->
       let private_key = Crypto_utils.get_key default_server_config.key_file in
       (* due to bleichenbacher attach, we should use a random pms *)
       (* then we do not leak any decryption or padding errors! *)
       let other = protocol_version_cstruct <> Rng.generate 46 in
       ( match Crypto.decryptRSA_unpadPKCS private_key kex with
         | None   -> return other
         | Some k ->
            ( match Reader.parse_version k with
              | Reader.Or_error.Ok c_ver ->
                 if ((Cstruct.len k) = 48) && (supported_protocol_version c_ver) then
                   return k
                 else
                   return other
              | Reader.Or_error.Error _ -> return other ) )

    | Ciphersuite.DHE_RSA ->
      (* we assume explicit communication here, not a client certificate *)
      ( match sp.dh_state with
        | `Sent (group, secret) -> return @@ DH.shared group secret kex
        | _                     -> fail Packet.HANDSHAKE_FAILURE  )

    | _ -> fail Packet.HANDSHAKE_FAILURE )

  >>= fun premastersecret ->
  let client_ctx, server_ctx, params =
    initialise_crypto_ctx sp premastersecret in
  let ps = packets @ [raw] in
  return (
      `KeysExchanged (`Crypted server_ctx, `Crypted client_ctx, params, ps),
      [], `Pass)

let answer_client_hello_params_int sp ch raw =
  let cipher = sp.ciphersuite in
  fail_false (List.mem cipher ch.ciphersuites) Packet.HANDSHAKE_FAILURE >>= fun () ->
  fail_false (supported_protocol_version ch.version) Packet.HANDSHAKE_FAILURE >>= fun () ->
  (* now we can provide a certificate with any of the given hostnames *)
  (match sp.server_name with
   | None   -> ()
   | Some x -> Printf.printf "was asked for hostname %s\n" x);
  let params = { sp with
                   server_random = Rng.generate 32 ;
                   client_random = ch.random } in
  (* RFC 4366: server shall reply with an empty hostname extension *)
  let host = match sp.server_name with
    | None   -> []
    | Some _ -> [Hostname None]
  in
  let secren = SecureRenegotiation
                 (params.client_verify_data <> params.server_verify_data)
  in
  let server_hello : server_hello =
    { version      = default_config.protocol_version ;
      random       = params.server_random ;
      sessionid    = None ;
      ciphersuites = cipher ;
      extensions   = secren :: host } in
  let bufs = [Writer.assemble_handshake (ServerHello server_hello)] in
  let kex = Ciphersuite.ciphersuite_kex cipher in
  ( if Ciphersuite.needs_certificate kex then
      let pem = Crypto_utils.read_pem_file default_server_config.certificate_file in
      let cert = Crypto_utils.pem_to_cstruct pem in
      let asn = Crypto_utils.pem_to_cert pem in
      return (bufs @ [Writer.assemble_handshake (Certificate [cert])],
              { params with server_certificate = Some asn })
    else
      return (bufs, params) )

  >>= fun (bufs', params') ->
  ( if Ciphersuite.needs_server_kex kex then
      match kex with
      | Ciphersuite.DHE_RSA ->

          (* XXX
           * Can move group selection up into default params, or pick a group of
           * different size in this spot. *)
          let group         = DH.Group.oakley_2 in (* rfc2409 1024-bit group *)
          let (secret, msg) = DH.gen_secret group in
          let dh_state      = `Sent (group, secret) in
          let written =
            let dh_param = Crypto.dh_params_pack group msg in
            Writer.assemble_dh_parameters dh_param in
          let data    = params'.client_random <> params'.server_random <> written in
          let signing = Hash.( MD5.digest data <> SHA1.digest data ) in

          match
            Crypto.padPKCS1_and_signRSA
                (Crypto_utils.get_key default_server_config.key_file)
                signing
          with
          | Some sign ->
              let kex =
                Writer.assemble_dh_parameters_and_signature written sign in
              return ( bufs' @ [Writer.assemble_handshake (ServerKeyExchange kex)]
                     , { params' with dh_state } )

          | None -> fail Packet.HANDSHAKE_FAILURE

    else return (bufs', params') )

  >>= fun (bufs'', params'') ->
  (* server hello done! *)
  let hello_done = Writer.assemble_handshake ServerHelloDone in
  let packets = bufs'' @ [hello_done] in
  return (`Handshaking (params'', raw :: packets),
          List.map (fun e -> `Record (Packet.HANDSHAKE, e)) packets,
          `Pass)

let answer_client_hello_params sp ch raw =
  let expected = sp.client_verify_data in
  check_reneg expected ch.extensions >>= fun () ->
  let host = find_hostname ch in
  fail_false (sp.server_name = host) Packet.HANDSHAKE_FAILURE >>= fun () ->
  answer_client_hello_params_int sp ch raw

let answer_client_hello (ch : client_hello) raw =
  fail_false (List.mem Ciphersuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV ch.ciphersuites) Packet.NO_RENEGOTIATION >>= fun () ->
  let issuported = fun x -> List.mem x ch.ciphersuites in
  fail_false (List.exists issuported default_config.ciphers) Packet.HANDSHAKE_FAILURE >>= fun () ->
  let cipher = List.hd (List.filter issuported default_config.ciphers) in
  let server_name = find_hostname ch in
  let params = { entity                = Server ;
                 ciphersuite           = cipher ;
                 master_secret         = Cstruct.create 0 ;
                 client_random         = Cstruct.create 0 ;
                 server_random         = Cstruct.create 0 ;
                 dh_state              = `Initial ;
                 server_certificate    = None ;
                 client_verify_data    = Cstruct.create 0 ;
                 server_verify_data    = Cstruct.create 0 ;
                 server_name }
  in
  answer_client_hello_params_int params ch raw

let handle_change_cipher_spec = function
  | `KeysExchanged (enc, dec, _, _) as is ->
     let ccs = change_cipher_spec in
     return (is, [`Record ccs; `Change_enc enc], `Change_dec dec)
  | _ -> fail Packet.UNEXPECTED_MESSAGE

let handle_handshake is buf =
  match Reader.parse_handshake buf with
  | Reader.Or_error.Ok handshake ->
     Printf.printf "HANDSHAKE: %s" (Printer.handshake_to_string handshake);
     Cstruct.hexdump buf;
     ( match (is, handshake) with
       | `Initial, ClientHello ch ->
          answer_client_hello ch buf
       | `Handshaking (p, bs), ClientKeyExchange kex ->
          answer_client_key_exchange p bs kex buf
       | `KeysExchanged (_, _, p, bs), Finished fin ->
          answer_client_finished p bs fin buf
       | `Established sp, ClientHello ch -> (* key renegotiation *)
          answer_client_hello_params sp ch buf
       | _, _-> fail Packet.HANDSHAKE_FAILURE )
  | _                           ->
     fail Packet.UNEXPECTED_MESSAGE

let handle_record
: tls_internal_state -> Packet.content_type -> Cstruct.t
  -> (tls_internal_state * rec_resp list * dec_resp) or_error
= fun is ct buf ->
  Printf.printf "HANDLE_RECORD (in state %s) %s\n"
                (state_to_string is)
                (Packet.content_type_to_string ct);
  match ct with
  | Packet.ALERT -> handle_alert buf
  | Packet.APPLICATION_DATA ->
     Printf.printf "APPLICATION DATA";
     Cstruct.hexdump buf;
     ( match is with
       | `Established _ -> return (is, [], `Pass)
       | _              -> fail Packet.UNEXPECTED_MESSAGE
     )
  | Packet.CHANGE_CIPHER_SPEC -> handle_change_cipher_spec is
  | Packet.HANDSHAKE -> handle_handshake is buf

let handle_tls = handle_tls_int handle_record
