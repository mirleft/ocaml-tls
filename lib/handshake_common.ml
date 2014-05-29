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

let rec check_reneg expected = function
  | []                       -> fail Packet.NO_RENEGOTIATION
  | SecureRenegotiation x::_ -> guard (Cs.equal expected x) Packet.NO_RENEGOTIATION
  | _::xs                    -> check_reneg expected xs

