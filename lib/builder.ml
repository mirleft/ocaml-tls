
type t = int * (Cstruct.t -> int -> unit)

let len (x, _) = x

let write (_, f) ?(off=0) buf = f buf off 
let to_cstruct (x, f as w) =
  let cs = Cstruct.create x in
  ( write w cs ; cs )
  

let (<>) (l1, f1) (l2, f2) =
  let f cs off = ( f1 cs off ; f2 cs (l1 + off) ) in
  (l1 + l2, f)

let append = (<>)

let pack x f = (x, f)

let of_string str =
  let n = String.length str in
  let f cs off = Cstruct.blit_from_string str 0 cs off n in
  (n, f)

let of_cstruct cs' =
  let n = Cstruct.len cs' in
  let f cs off = Cstruct.blit cs' 0 cs off n in
  (n, f)


