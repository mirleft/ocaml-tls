
open Sexplib

type id

val trace   : unit -> unit
val untrace : unit -> unit

val create : unit -> id

val tracing_with : id:id -> (unit -> 'a) -> 'a

val sexp      : tag:string -> Sexp.t Lazy.t -> unit
val sexp_with : tag:string -> sexpf:('a -> Sexp.t) -> 'a -> unit
val cs        : tag:string -> Cstruct.t -> unit

val get_trace : id -> Sexp.t list

module Monadic (M : Control.Monad) : sig
  val create : unit -> id
  val tracing_with : id:id -> (unit -> 'a M.t) -> 'a M.t
  val sexp      : tag:string -> Sexp.t Lazy.t -> unit M.t
  val sexp_with : tag:string -> sexpf:('a -> Sexp.t) -> 'a -> unit M.t
  val cs        : tag:string -> Cstruct.t -> unit M.t
end

val sexp_of_id : id -> Sexp.t
val id_of_sexp : Sexp.t -> id
