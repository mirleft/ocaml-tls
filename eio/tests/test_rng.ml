(* Insecure predictable RNG for fuzz testing. *)

type g = int ref

let block = 1

let create ?time:_ () = ref 1234

let generate_into ~g buf ~off n =
  for i = off to off + n - 1 do
    Bytes.set_uint8 buf i !g;
    g := !g + 1
  done

let reseed ~g:_ _ = ()

let accumulate ~g:_ _ = `Acc ignore

let seeded ~g:_ = true

let pools = 0
