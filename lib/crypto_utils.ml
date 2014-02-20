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


open Bigarray
let bytes_of_string string =
  let length = String.length string in
  let arr = Array1.create int8_unsigned c_layout length in
  for i = 0 to length - 1 do arr.{i} <- int_of_char string.[i] done;
  arr

let pem_to_cstruct pem =
  let str =
    Cryptokit.(transform_string (Base64.decode ()) pem) in
  ( match
      Asn_grammars.certificate_of_cstruct (Cstruct.of_string str)
    with
    | None               -> Printf.printf "decoding failed"
    | Some (cert, bytes) -> Printf.printf "decoded cert" );
  Cstruct.of_string str

let get_cert_from_file filename =
  let pem = read_pem_file filename in
  pem_to_cstruct pem

let bin_of_int d =
  if d = 0 then "0" else
  let rec aux acc d =
    if d = 0 then acc else
    aux (string_of_int (d land 1) :: acc) (d lsr 1)
  in
  String.concat "" (aux [] d)

let get_key =
  let pem = read_pem_file "server.key" in
  let str = Cryptokit.(transform_string (Base64.decode ()) pem)
  in
  let Some (pk, _) =
    Asn_grammars.rsa_private_key_of_cstruct (Cstruct.of_string str) in
  String.
    (Printf.printf "got a private key %d %d %d %d %d %d %d %d\n"
       (length pk.n)
       (length pk.e)
       (length pk.d)
       (length pk.p)
       (length pk.q)
       (length pk.dp)
       (length pk.dq)
       (length pk.qinv)) ;
  pk

let encrypt msg =
  let crprivate = get_key in
  let enc = Cryptokit.RSA.encrypt crprivate msg in
  Printf.printf "enc is %s\n" enc;
  enc

let decrypt msg =
  let crprivate = get_key in
  let dec = Cryptokit.RSA.decrypt crprivate msg in
  Printf.printf "dec is %s\n" dec;
  dec
