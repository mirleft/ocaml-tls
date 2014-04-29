
let cs_mmap file =
  Unix_cstruct.of_fd Unix.(openfile file [O_RDONLY] 0)

let load_priv () =
  let cs1 = cs_mmap "./certificates/server.pem"
  and cs2 = cs_mmap "./certificates/server.key" in
  Tls.X509.(Cert.of_pem_cstruct1 cs1, PK.of_pem_cstruct1 cs2) 

let _ =
  let loops =
    try int_of_string Sys.argv.(1) with _ -> 10
  and size  =
    try int_of_string Sys.argv.(2) with _ -> 1024
  and cert  = load_priv ()
  in
  Testlib.loop_chatter ~cert ~loops ~size

