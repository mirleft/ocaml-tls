
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
  let str =
    Cryptokit.(transform_string (Base64.decode ()) pem) in
  Cstruct.of_string str

let pem_to_cert pem =
  let cs = pem_to_cstruct pem in
  match Asn_grammars.certificate_of_cstruct cs with
  | None           -> failwith "pem decode failed"
  | Some (cert, _) -> cert

let cert_cstruct_of_file filename =
  let pem = read_pem_file filename in pem_to_cstruct pem

let cert_of_file filename =
  let pem = read_pem_file filename in pem_to_cert pem

let get_key filename =
  let pem = read_pem_file filename in
  let str = Cryptokit.(transform_string (Base64.decode ()) pem)
  in
  match
    Asn_grammars.rsa_private_of_cstruct (Cstruct.of_string str)
  with
  | None         -> assert false
  | Some (pk, _) -> pk

let the_key = lazy (get_key "server.key")
