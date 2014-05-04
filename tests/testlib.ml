
open OUnit2

let time f =
  let t1 = Sys.time () in
  let r  = f () in
  let t2 = Sys.time () in
  ( Printf.eprintf "[time] %f.04 s\n%!" (t2 -.  t1) ; r )

let (<>) = Tls.Utils.Cs.(<>)

let list_to_cstruct xs =
  let open Cstruct in
  let buf = create (List.length xs) in
  List.iteri (set_uint8 buf) xs ;
  buf

let uint16_to_cstruct i =
  let open Cstruct in
  let buf = create 2 in
  BE.set_uint16 buf 0 i;
  buf

let assert_cs_eq ?msg cs1 cs2 =
  assert_equal
    ~cmp:Tls.Utils.Cs.equal
    ~printer:Tls.Utils.hexdump_to_str
    ?msg
    cs1 cs2
