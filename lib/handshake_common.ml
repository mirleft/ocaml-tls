open Utils
open Core

let change_cipher_spec =
  (Packet.CHANGE_CIPHER_SPEC, Writer.assemble_change_cipher_spec)

let find_hostname : 'a hello -> string option =
  fun h ->
    let hexts = List.filter (function
                               | Hostname _ -> true
                               | _          -> false)
                             h.extensions
    in
    match hexts with
    | [Hostname name] -> name
    | _               -> None

let get_secure_renegotiation exts =
  map_find
    exts
    ~f:(function SecureRenegotiation data -> Some data | _ -> None)

(* find highest version between v and supported versions *)
let supported_protocol_version versions v =
  (* implicitly assumes that versions is without any holes *)
  let max = max_protocol_version versions in
  let min = min_protocol_version versions in
  match v >= max, v >= min with
    | true, _    -> Some max
    | _   , true -> Some v
    | _   , _    -> None
