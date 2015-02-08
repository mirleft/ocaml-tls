
open Sexplib
open Sexp

let record kvs =
  List List.(map (fun (k, v) -> (List [Atom k; v])) kvs)
