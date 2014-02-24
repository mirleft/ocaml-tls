

(*
 * MORNING PRAYER:
 *
 * I will allocate data, more and more data and all new data, since i'm not
 * writing C like a peasant.
 *
 * This kinda travesty will go away. After we reach correctness. Not before.
 *)

let cs_appends csn =
  let cs =
    Cstruct.create @@
      List.fold_left (fun x cs -> x + Cstruct.len cs) 0 csn in
  let _ =
    List.fold_left
      (fun off e ->
        let len = Cstruct.len e in
        ( Cstruct.blit e 0 cs off len ; off + len ))
      0 csn in
  cs

let cs_append cs1 cs2 = cs_appends [ cs1; cs2 ]

let cs_canonicalize cs =
  if cs.Cstruct.off = 0 then cs else
    Cstruct.(of_bigarray @@
                Bigarray.Array1.sub cs.buffer cs.off cs.len)

let cs_eq cs1 cs2 = cs_canonicalize cs1 = cs_canonicalize cs2
