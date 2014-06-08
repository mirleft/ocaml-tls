
open Sexplib

val the_function : hook:(Sexp.t -> unit) -> (unit -> 'a) -> 'a

val sexp  : tag:string -> Sexp.t Lazy.t -> unit
val sexpf : tag:string -> sexpf:('a -> Sexp.t) -> 'a -> unit
val cs    : tag:string -> Cstruct.t -> unit

