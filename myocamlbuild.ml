open Ocamlbuild_plugin

let runtime_deps_of_ppx ppx =
  (Findlib.query "ppx_sexp_conv").dependencies
  |> List.filter_opt (fun { Findlib.name; _ } ->
      if name = ppx || name = "ppx_deriving" then
        None
      else
        Some name)

let () = dispatch (function
    | After_rules ->
      let meta = "pkg/META" in
      let meta_in = meta ^ ".in" in
      rule meta ~dep:meta_in ~prod:meta (fun _ _ ->
          let deps = String.concat " " (runtime_deps_of_ppx "ppx_sexp_conv") in
          Echo([String.subst "PPX_SEXP_CONV_RUNTIME" deps
                  (Pathname.read meta_in)],
               meta))
    | _ -> ())
