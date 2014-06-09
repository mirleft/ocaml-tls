
open Sexplib

module Cstruct_s = struct

  type t = Cstruct.t

  (* XXX Maybe hexdump these..? *)

  let t_of_sexp sexp =
    failwith "can't decode Cstruct.t from sexp"
(*     Cstruct.of_string (Conv.string_of_sexp sexp) *)

  let hex_of_byte =
    Array.(get @@ init 256 (Printf.sprintf "%02x"))

  let sexp_of_t cs =
    let open Buffer in
    let n   = Cstruct.len cs - 1 in
    let buf = create 32 in
    add_string buf "#(" ;
    for i = 0 to n do
      add_string buf @@ hex_of_byte Cstruct.(get_uint8 cs i) ;
      if (succ i) mod 32 = 0 && i < n then
        add_string buf " \n "
      else if (succ i) mod 8 = 0 && i < n then
        add_char buf ' '
    done ;
    add_string buf ")" ;
    Sexp.Atom (contents buf)

(*     Conv.sexp_of_string (Cstruct.to_string cs) *)

end

let record kvs =
  Sexp.List List.(map (fun (k, v) -> Sexp.(List [Atom k; v])) kvs)
