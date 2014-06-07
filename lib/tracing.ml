
type id = Sexp_ext.Cstruct_s.t with sexp

let is_tracing = ref false
let trace   () = is_tracing := true
and untrace () = is_tracing := false


(* This is so not thread-safe it's not even funny. *)
let current = ref None
let traces  = Hashtbl.create 32

let form_trace id sexp =
  let open Sexplib in
  Sexp.(List [ Atom id ; sexp ])

(* Sort-of dynamic variable for a single thread. *)
let tracing_with ~id f =
  match !is_tracing with
  | false -> f ()
  | true  ->
      let last = !current in
      current := Some id ;
      try
        let res = f () in
        ( current := last ; res )
      with exn -> ( current := last ; raise exn )

let sexp ~tag lz =
  match !current with
  | None    -> ()
  | Some id ->
      let s   = form_trace tag (Lazy.force lz)
      and seq = Hashtbl.find traces id in
      seq := (s :: !seq)

let sexp_with ~tag ~sexpf x = sexp ~tag @@ lazy (sexpf x)

let cs ~tag =
  sexp_with ~tag ~sexpf:Sexp_ext.Cstruct_s.sexp_of_t

let create () =
  let id = Nocrypto.Rng.generate 32 in
  ( Hashtbl.replace traces id (ref []) ; id )

let get_trace id =
  let seq = Hashtbl.find traces id in
  ( Hashtbl.remove traces id ; List.rev !seq )


module Monadic (M : Control.Monad) = struct

  let create = create

  let tracing_with = tracing_with

  let sexp ~tag lz = sexp ~tag lz ; M.return ()

  let sexp_with ~tag ~sexpf x =
    sexp_with ~tag ~sexpf x ; M.return ()

  let cs ~tag x = cs ~tag x ; M.return ()

end
