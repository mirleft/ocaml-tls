
open Utils

module Pem = struct

  open Cstruct

  let open_begin = of_string "-----BEGIN "
  and open_end   = of_string "-----END "
  and close      = of_string "-----"

  let catch f a =
    try Some (f a) with Invalid_argument _ -> None

  let tok_of_line cs =
    try
      if ( cs_eq cs cs_empty ) then
        `Empty else
      if ( get_char cs 0 = '#' ) then
        `Empty else
      if ( cs_begins_with cs open_begin &&
           cs_ends_with cs close ) then
        `Begin (to_string @@ sub cs 11 (len cs - 16)) else
      if ( cs_begins_with cs open_end &&
           cs_ends_with cs close ) then
        `End (to_string @@ sub cs 9 (len cs - 14)) else
        `Data cs
    with Invalid_argument _ -> `Data cs

  let chop cs off len =
    let (a, b) = split cs off in (a, shift b len)

  let rec lines cs =
    let rec eol i =
      match get_char cs i with
      | '\r' when get_char cs (i + 1) = '\n' -> chop cs i 2
      | '\n' -> chop cs i 1
      | _    -> eol (i + 1) in
    match catch eol 0 with
    | Some (a, b) -> [< 'tok_of_line a ; lines b >]
    | None        -> [< 'tok_of_line cs >]

  let combine ilines =

    let rec accumulate t acc = parser
      | [< ' `Empty ; lines >] -> accumulate t acc lines
      | [< ' `Data cs ; lines >] -> accumulate t (cs :: acc) lines
      | [< ' `End t' when t = t' >] -> cs_appends (List.rev acc)

    and block = parser
      | [< ' `Begin t ; body = accumulate t [] ; tail >] ->
        ( match catch Nocrypto.Base64.decode body with
          | None      -> invalid_arg "PEM: malformed Base64 data"
          | Some data -> (t, data) :: block tail )
      | [< ' _ ; lines >] -> block lines
      | [< >] -> []

    in block ilines

  let parse = o combine lines

end

let exactly_one ~what = function
  | []  -> invalid_arg ("No " ^ what)
  | [x] -> x
  | _   -> invalid_arg ("Multiple " ^ what)

module Cert = struct

  open Certificate

  type t = certificate

  let of_pem_cstruct cs =
    List.fold_left (fun certs -> function
      | ("CERTIFICATE", raw) ->
        ( match Asn_grammars.certificate_of_cstruct raw with
          | Some asn -> { asn ; raw } :: certs
          | None -> invalid_arg "X509: failed to parse certificate" )
      | _ -> certs)
    []
    (Pem.parse cs)

  let of_pem_cstruct1 =
    o (exactly_one ~what:"certificates") of_pem_cstruct
end

module PK = struct

  type t = Nocrypto.Rsa.priv

  let of_pem_cstruct cs =
    List.fold_left (fun pks -> function
      | ("RSA PRIVATE KEY", cs) ->
        ( match Asn_grammars.PK.rsa_private_of_cstruct cs with
          | Some pk -> pk :: pks
          | None    -> invalid_arg "X509: failed to parse rsa private key" )
      | _ -> pks)
    []
    (Pem.parse cs)

  let of_pem_cstruct1 =
    o (exactly_one ~what:"rsa keys") of_pem_cstruct
end

module Validator : sig

  type t

  val validate : t -> ?servername:string -> Cstruct.t list ->
                  [ `Ok of Cert.t | `Fail of Certificate.certificate_failure ]

  val chain_of_trust : time:int -> Cert.t list -> t
  val null : t
end
  =
struct

  (* XXX Validator returns server cert since it does the parsing.
   * Factor this out to avoid the crock? *)
  type t = ?servername:string -> time:int -> Cstruct.t list ->
              [ `Ok of Cert.t | `Fail of Certificate.certificate_failure ]

  let validate t ?servername stack =
    t ?servername ~time:0 stack

  (* XXX
   * Validator just hands off a list of certs. Should be indexed. *)
  let chain_of_trust ~time cas =
    let cas = Certificate.validate_cas ~time cas in
    fun ?servername ~time stack ->
      Certificate.verify_chain_of_trust ?servername ~time ~anchors:cas stack

  let null ?servername:_ ~time:_ = Certificate.server_of_stack

end

