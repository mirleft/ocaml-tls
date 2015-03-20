open Tls

(* am I really bold enough to define equality? *)
let rec exts_eq a b =
  let open Core in
  match a with
  | [] -> true
  | x::xs ->
    exts_eq xs b &&
    match x with
    | Hostname s ->
      ( try (match List.find (function Hostname _ -> true | _ -> false) b, s with
            | Hostname None, None -> true
            | Hostname (Some x), Some y when x = y -> true
            | _ -> false
          ) with Not_found -> false )
    | MaxFragmentLength mfl ->
      ( try (match List.find (function MaxFragmentLength _ -> true | _ -> false) b, mfl with
            | MaxFragmentLength x, y when x = y -> true
            | _ -> false
          ) with Not_found -> false )
    | EllipticCurves ncs ->
      ( try (match List.find (function EllipticCurves _ -> true | _ -> false) b with
            | EllipticCurves x -> List.for_all (fun ec -> List.mem ec x) ncs
            | _ -> false
          ) with Not_found -> false )
    | ECPointFormats ecp ->
      ( try (match List.find (function ECPointFormats _ -> true | _ -> false) b with
            | ECPointFormats x -> List.for_all (fun ec -> List.mem ec x) ecp
            | _ -> false
          ) with Not_found -> false )
    | SecureRenegotiation sn -> (* actually, if sn empty might also be ciphersuite! *)
      ( try (match List.find (function SecureRenegotiation _ -> true | _ -> false) b with
            | SecureRenegotiation sn' -> Nocrypto.Uncommon.Cs.equal sn sn'
            | _ -> false
          ) with Not_found -> false )
    | Padding _ -> true
    | SignatureAlgorithms hs ->
      ( try (match List.find (function SignatureAlgorithms _ -> true | _ -> false) b with
            | SignatureAlgorithms hs' -> List.for_all (fun hs -> List.mem hs hs') hs
            | _ -> false
          ) with Not_found -> false )
    | UnknownExtension (num, data) ->
      ( try (match List.find (function UnknownExtension (x, _) when x = num -> true | _ -> false) b with
            | UnknownExtension (_, data') -> Nocrypto.Uncommon.Cs.equal data data'
            | _ -> false
          ) with Not_found -> false )

let hello_eq (a : ('a, 'b) Core.hello) (b : ('a, 'b) Core.hello) cs_cmp =
  let open Core in
  let cs_eq = Nocrypto.Uncommon.Cs.equal in
  a.version = b.version &&
  cs_eq a.random b.random &&
  (match a.sessionid, b.sessionid with
   | None, None -> true
   | Some a, Some b -> cs_eq a b
   | _ -> false) &&
  cs_cmp a.ciphersuites b.ciphersuites &&
  exts_eq a.extensions b.extensions

let handshake_equal a b =
  let open Core in
  let cs_eq = Nocrypto.Uncommon.Cs.equal in
  match a, b with
  | HelloRequest, HelloRequest -> true
  | ServerHelloDone, ServerHelloDone -> true
  | ClientHello ch, ClientHello ch' -> hello_eq ch ch' (fun a b -> List.for_all (fun c -> List.mem c b) a)
  | ServerHello sh, ServerHello sh' -> hello_eq sh sh' (fun a b -> a = b)
  | Certificate c, Certificate c' -> List.length c = List.length c' && List.for_all (fun (a, b) -> cs_eq a b) (List.combine c c')
  | ServerKeyExchange skex, ServerKeyExchange skex' -> cs_eq skex skex'
  | CertificateRequest cr, CertificateRequest cr' -> cs_eq cr cr' (* should do modulo CA list *)
  | ClientKeyExchange ckex, ClientKeyExchange ckex' -> cs_eq ckex ckex'
  | CertificateVerify cv, CertificateVerify cv' -> cs_eq cv cv'
  | Finished f, Finished f' -> cs_eq f f'
  | _ -> false

let record_equal (ahdr, adata) (bhdr, bdata) =
  (* Printf.printf "comparing %s with %s\n"
     (Packet.content_type_to_string ahdr.Core.content_type)
     (Packet.content_type_to_string bhdr.Core.content_type) ; *)
  match ahdr.Core.content_type, bhdr.Core.content_type with
  | Packet.CHANGE_CIPHER_SPEC, Packet.CHANGE_CIPHER_SPEC -> (true, None)
  | Packet.ALERT, Packet.ALERT -> (true, None) (* since we hangup after alert anyways *)
  | Packet.HANDSHAKE, Packet.HANDSHAKE ->
    ( match Engine.separate_handshakes adata, Engine.separate_handshakes bdata with
      | State.Ok (ahs, arest), State.Ok (bhs, brest) when
          (Cstruct.len arest = 0) && (Cstruct.len brest = 0) ->
        let cmp1 a b =
          match Reader.parse_handshake a, Reader.parse_handshake b with
          | Reader.Or_error.Ok a, Reader.Or_error.Ok b -> handshake_equal a b
          | _ -> false
        in
        let rec cmpn a b =
          match a, b with
          | x :: xs, y :: ys when cmp1 x y -> cmpn xs ys
          | xs, [] -> (true, Some (List.map (fun p -> (ahdr, p)) xs))
          | _ -> (false, None)
        in
        cmpn ahs bhs
      | _ -> (false, None) )
    | Packet.APPLICATION_DATA, Packet.APPLICATION_DATA -> (true, None) (* should I bother about payload? *)
  | _ -> (false, None)
