
type t

val len        : t -> int
val write      : w -> ?off:int -> Cstruct.t -> unit
val to_cstruct : t -> Cstruct.t

val (<>)   : t -> t -> t
val append : t -> t -> t

val pack       : int -> (Cstruct.t -> int -> unit) -> t
val of_string  : string -> t
val of_cstruct : Cstruct.t -> t

