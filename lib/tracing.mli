
open Sexplib

val active : hook:(Sexp.t -> unit) -> (unit -> 'a) -> 'a

val sexp  : tag:string -> Sexp.t Lazy.t -> unit
val sexpf : tag:string -> f:('a -> Sexp.t) -> 'a -> unit
val cs    : tag:string -> Cstruct.t -> unit

