
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

let get_cert_from_file filename =
  let pem = read_pem_file filename in pem_to_cstruct pem

let get_key filename =
  let pem = read_pem_file filename in
  let str = Cryptokit.(transform_string (Base64.decode ()) pem)
  in
  let Some (pk, _) =
    Asn_grammars.rsa_private_of_cstruct (Cstruct.of_string str) in
  String.
    (Printf.printf "got a private key %d %d %d %d %d %d %d %d\n"
       (length pk.n) (length pk.e ) (length pk.d ) (length pk.p)
       (length pk.q) (length pk.dp) (length pk.dq) (length pk.qinv));
  pk

let the_key = lazy (get_key "server.key")

let encrypt msg =
  let crprivate = Lazy.force the_key in
  let enc = Cryptokit.RSA.encrypt crprivate msg in
  Printf.printf "enc is %s\n" enc;
  enc

let decrypt msg =
  let crprivate = Lazy.force the_key in
  let dec = Cryptokit.RSA.decrypt crprivate msg in
  Printf.printf "dec is %s\n" dec;
  dec
