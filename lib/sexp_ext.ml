
open Sexplib

module Cstruct_s = struct

  type t = Cstruct.t

  (* XXX Maybe hexdump these..? *)

  let t_of_sexp sexp =
    Cstruct.of_string (Conv.string_of_sexp sexp)

  let sexp_of_t cs =
    Conv.sexp_of_string (Cstruct.to_string cs)

end

