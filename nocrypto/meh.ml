
open Bigarray

type bytes = (char, int8_unsigned_elt, c_layout) Array1.t
external sha1_bigarray : bytes -> bytes = "caml_DESU_sha1" 
external md5_bigarray  : bytes -> bytes = "caml_DESU_md5"

let sha1 cs =
  Cstruct.of_bigarray (sha1_bigarray (Cstruct.to_bigarray cs))

let md5 cs =
  Cstruct.of_bigarray (md5_bigarray (Cstruct.to_bigarray cs))

let () =
  let cs = Cstruct.of_string "desu" in
  Cstruct.hexdump (sha1 cs);
  Cstruct.hexdump (md5 cs)

