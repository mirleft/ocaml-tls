
open Nocrypto

let read_lines filename =
  let chan = open_in filename in
  let rec read () =
    try
      let line = input_line chan in line :: read ()
    with End_of_file -> ( close_in chan ; [] ) in
  read ()

let read_pem_file filename =
  let lines = read_lines filename in
  String.concat "" (List.filter (fun line -> line.[0] <> '-') lines)

let pem_to_cstruct pem =
  Base64.decode @@ Cstruct.of_string pem

let pem_to_cert pem =
  let cs = pem_to_cstruct pem in
  match Asn_grammars.certificate_of_cstruct cs with
  | None      -> failwith "pem decode failed"
  | Some cert -> cert

let cert_cstruct_of_file filename =
  let pem = read_pem_file filename in pem_to_cstruct pem

let certs_of_file : string -> (Asn_grammars.certificate * Cstruct.t) list =
  fun filename ->
    let lines = read_lines filename in
    let rec consume_cert acc = function
      | c::cs when c = "-----END CERTIFICATE-----" -> (acc, cs)
      | c::cs -> consume_cert (acc @ [c]) cs
      | _ -> assert false
    in
    let rec go cs = function
      | [] -> List.rev cs
      | l::ls when l = "-----BEGIN CERTIFICATE-----" ->
         let certlines, rt = consume_cert [] ls in
         go ((String.concat "" certlines) :: cs) rt
      | l::ls -> go cs ls
    in
    let certificates = go [] lines in
    List.combine (List.map pem_to_cert certificates)
                 (List.map pem_to_cstruct certificates)

let cert_of_file : string -> (Asn_grammars.certificate * Cstruct.t) =
  fun filename ->
    let pem = read_pem_file filename in
    (pem_to_cert pem, pem_to_cstruct pem)

let get_key filename =
  let enc = read_pem_file filename in
  let dec = Base64.decode (Cstruct.of_string enc) in
  match
    Asn_grammars.PK.rsa_private_of_cstruct dec
  with
  | None    -> assert false
  | Some pk -> pk

let the_key = lazy (get_key "server.key")
