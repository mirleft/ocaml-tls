
open Sexplib
open Sexp

module Cstruct_s = struct

  type t = Cstruct.t

  let (h_of_b, b_of_h) =
    let arr = Array.create 256 ""
    and ht  = Hashtbl.create 256 in
    for i = 0 to 255 do
      let str = Printf.sprintf "%02x" i in
      arr.(i) <- str ;
      Hashtbl.add ht str i
    done ;
    (Array.get arr, Hashtbl.find ht)

  let t_of_sexp sexp =

    let failure msg sexp =
      Conv.of_sexp_error ("Cstruct_s.t_of_sexp: " ^ msg ^ " needed") sexp in

    let rec measure a = function
      | Atom _  -> a + 1
      | List xs -> List.fold_left measure a xs

    and write i cs l1 = function
      | (Atom str as sexp)::l2 ->
          let b =
            try b_of_h str with Not_found -> failure "hex byte" sexp in
          Cstruct.set_uint8 cs i b ;
          write (succ i) cs l1 l2
      | sexp :: _ -> failure "atom" sexp
      | []        ->
          match l1 with
          | List l2::l1' -> write i cs l1' l2
          | sexp   ::_   -> failure "inner list" sexp
          | []           -> ()
    in
    match sexp with
    | Atom _           -> failure "list" sexp
    | List list as exp ->
        let cs = Cstruct.create (measure 0 exp) in
        ( write 0 cs list [] ; cs )


  let cs_fold_bytes ~f ~init cs =
    let acc = ref init in
    for i = 0 to Cstruct.len cs - 1 do
      acc := f !acc i Cstruct.(get_uint8 cs i)
    done ;
    !acc

  let sexp_of_t cs =
    let of_list list = List (List.rev list) in
    let append big = function
      | []    -> big
      | small -> of_list small :: big in
    let (l1, l2) =
      cs_fold_bytes
      ~f:(fun (l1, l2 as acc) i b ->
          let (l1, l2) =
            if i mod 16 = 0 then
              (append l1 l2, [])
            else acc in
          (l1, Atom (h_of_b b) :: l2))
      ~init:([], [])
      cs in
    of_list @@ append l1 l2

end

let record kvs =
  List List.(map (fun (k, v) -> (List [Atom k; v])) kvs)
