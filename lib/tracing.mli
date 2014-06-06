
type id

val trace   : unit -> unit
val untrace : unit -> unit

val create : unit -> id

val item : id:id -> Sexplib.Type.t Lazy.t -> unit
val item_with : id:id -> sexpf:('a -> Sexplib.Type.t) -> 'a -> unit
val cs   : id:id -> tag:string -> Cstruct.t -> unit

val get_trace : id -> Sexplib.Type.t list

