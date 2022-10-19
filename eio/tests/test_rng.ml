(* Insecure predictable RNG for fuzz testing. *)

type g = int ref

let block = 1

let create ?time:_ () = ref 1234

let generate ~g n =
  let cs = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 cs i !g;
    g := !g + 1
  done;
  cs

let reseed ~g:_ _ = ()

let accumulate ~g:_ _ = `Acc ignore

let seeded ~g:_ = true

let pools = 0
