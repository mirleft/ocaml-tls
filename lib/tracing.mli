
type id

val trace   : unit -> unit
val untrace : unit -> unit

val create : unit -> id

val item : id -> string Lazy.t -> unit
val get_trace : id -> string list

