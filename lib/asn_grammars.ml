open Asn

type bits = Cstruct.t

let def  x = function None -> x | Some y -> y
let def' x = fun y -> if y = x then None else Some y

(* Error out on trailing bytes. *)
(* XXX Is there a place where we need bytes after an ASN structure? *)
let decode_strict codec cs =
  match decode codec cs with
  | Some (a, cs') when Cstruct.len cs' = 0 -> Some a
  | _                                      -> None

let projections encoding asn =
  let c = codec encoding asn in (decode_strict c, encode c)

let compare_unordered_lists cmp l1 l2 =
  let rec loop = function
    | (x::xs, y::ys) -> ( match cmp x y with 0 -> loop (xs, ys) | n -> n )
    | ([], [])       ->  0
    | ([], _ )       -> -1
    | (_ , [])       ->  1
  in
  loop List.(sort cmp l1, sort cmp l2)

let parse_error_oid msg oid =
  parse_error @@ msg ^ ": " ^ OID.to_string oid

(*
 * A way to parse by propagating (and contributing to) exceptions, so those can
 * be handles up in a single place. Meant for parsing embedded structures.
 *
 * XXX Would be nicer if combinators could handle embedded structures.
 *)
let project_exn asn =
  let c = codec der asn in
  let dec cs =
    let (res, cs') = decode_exn c cs in
    if Cstruct.len cs' = 0 then res else parse_error "embed: leftovers"
  in
  (dec, encode c)


let display_text =
  map (function `C1 s -> s | `C2 s -> s | `C3 s -> s | `C4 s -> s)
      (fun s -> `C4 s)
  @@
  choice4 ia5_string visible_string bmp_string utf8_string

module Name = struct

  (* ASN `Name' fragmet appears all over. *)

  (* rfc5280 section 4.1.2.4 - name components we "must" handle. *)
  (* A list of abbreviations: http://pic.dhe.ibm.com/infocenter/wmqv7/v7r1/index.jsp?topic=%2Fcom.ibm.mq.doc%2Fsy10570_.htm *)
  (* Also rfc4519. *)

  type component =
    | CN           of string
    | Serialnumber of string
    | C            of string
    | L            of string
    | SP           of string
    | O            of string
    | OU           of string
    | T            of string
    | DNQ          of string
    | Mail         of string
    | DC           of string

    | Given_name   of string
    | Surname      of string
    | Initials     of string
    | Pseudonym    of string
    | Generation   of string

    | Other        of OID.t * string

  type dn = component list

  (* See rfc5280 section 4.1.2.4. *)
  let directory_name =
    let f = function | `C1 s -> s | `C2 s -> s | `C3 s -> s
                     | `C4 s -> s | `C5 s -> s | `C6 s -> s
    and g s = `C1 s in
    map f g @@
    choice6
      utf8_string printable_string
      ia5_string universal_string teletex_string bmp_string


  (* We flatten the sequence-of-set-of-tuple here into a single list.
  * This means that we can't write non-singleton sets back.
  * Does anyone need that, ever?
  *)

  let name =
    let open Registry in

    let a_f = function
      | (oid, x ) when oid = domain_component              -> DC           x 
      | (oid, x ) when oid = X520.common_name              -> CN           x 
      | (oid, x ) when oid = X520.serial_number            -> Serialnumber x 
      | (oid, x ) when oid = X520.country_name             -> C            x 
      | (oid, x ) when oid = X520.locality_name            -> L            x 
      | (oid, x ) when oid = X520.state_or_province_name   -> SP           x 
      | (oid, x ) when oid = X520.organization_name        -> O            x 
      | (oid, x ) when oid = X520.organizational_unit_name -> OU           x 
      | (oid, x ) when oid = X520.title                    -> T            x 
      | (oid, x ) when oid = X520.dn_qualifier             -> DNQ          x 
      | (oid, x ) when oid = PKCS9.email                   -> Mail         x 
      | (oid, x ) when oid = X520.given_name               -> Given_name   x 
      | (oid, x ) when oid = X520.surname                  -> Surname      x 
      | (oid, x ) when oid = X520.initials                 -> Initials     x 
      | (oid, x ) when oid = X520.pseudonym                -> Pseudonym    x 
      | (oid, x ) when oid = X520.generation_qualifier     -> Generation   x 
      | (oid, x)                                           -> Other (oid, x)

    and a_g = function
      | DC           x   -> (domain_component              , x )
      | CN           x   -> (X520.common_name              , x )
      | Serialnumber x   -> (X520.serial_number            , x )
      | C            x   -> (X520.country_name             , x )
      | L            x   -> (X520.locality_name            , x )
      | SP           x   -> (X520.state_or_province_name   , x )
      | O            x   -> (X520.organization_name        , x )
      | OU           x   -> (X520.organizational_unit_name , x )
      | T            x   -> (X520.title                    , x )
      | DNQ          x   -> (X520.dn_qualifier             , x )
      | Mail         x   -> (PKCS9.email                   , x )
      | Given_name   x   -> (X520.given_name               , x )
      | Surname      x   -> (X520.surname                  , x )
      | Initials     x   -> (X520.initials                 , x )
      | Pseudonym    x   -> (X520.pseudonym                , x )
      | Generation   x   -> (X520.generation_qualifier     , x )
      | Other (oid,  x ) -> (oid                           , x )
    in

    let attribute_tv =
      map a_f a_g @@
      sequence2
        (required ~label:"attr type"  oid)
        (* This is ANY according to rfc5280. *)
        (required ~label:"attr value" directory_name) in
    let rd_name      = set_of attribute_tv in
    let rdn_sequence =
      map List.concat (List.map (fun x -> [x]))
      @@
      sequence_of rd_name
    in
    rdn_sequence (* A vacuous choice, in the standard. *)

  (* rfc5280 section 7.1. -- we're too strict on strings and should preserve the
   * order. *)
  let equal n1 n2 = compare_unordered_lists compare n1 n2 = 0

end

module General_name = struct

  (* GeneralName is also pretty pervasive. *)

  (* OID x ANY. Hunt down the alternatives.... *)
  let another_name =
    let open Registry.Name_extn in
    let f = function
      | (oid, `C1 n) when oid = venezuela_1 || oid = venezuela_2 -> n
      | (oid, _    ) -> parse_error_oid "AnotherName: unrecognized oid" oid
    and g = fun _ ->
      invalid_arg "can't encode AnotherName extensions, yet."
    in
    map f g @@
    sequence2
      (required ~label:"type-id" oid)
      (required ~label:"value" @@
        explicit 0
          (choice2 utf8_string null))

  and or_address = null (* Horrible crap, need to fill it. *)

  let edi_party_name =
    sequence2
      (optional ~label:"nameAssigner" @@ implicit 0 Name.directory_name)
      (required ~label:"partyName"    @@ implicit 1 Name.directory_name)

  type t =
    | Other         of string    (* another_name *)
    | Rfc_822       of string
    | DNS           of string
    | X400_address  of unit      (* or_address *)
    | Directory     of Name.dn
    | EDI_party     of (string option * string)
    | URI           of string
    | IP            of Cstruct.t (* ... decode? *)
    | Registered_id of OID.t

  let general_name =

    let f = function
      | `C1 (`C1 x) -> Other         x
      | `C1 (`C2 x) -> Rfc_822       x
      | `C1 (`C3 x) -> DNS           x
      | `C1 (`C4 x) -> X400_address  x
      | `C1 (`C5 x) -> Directory     x
      | `C1 (`C6 x) -> EDI_party     x
      | `C2 (`C1 x) -> URI           x
      | `C2 (`C2 x) -> IP            x
      | `C2 (`C3 x) -> Registered_id x

    and g = function
      | Other         x -> `C1 (`C1 x)
      | Rfc_822       x -> `C1 (`C2 x)
      | DNS           x -> `C1 (`C3 x)
      | X400_address  x -> `C1 (`C4 x)
      | Directory     x -> `C1 (`C5 x)
      | EDI_party     x -> `C1 (`C6 x)
      | URI           x -> `C2 (`C1 x)
      | IP            x -> `C2 (`C2 x)
      | Registered_id x -> `C2 (`C3 x)
    in

    map f g @@
    choice2
      (choice6
        (implicit 0 another_name)
        (implicit 1 ia5_string)
        (implicit 2 ia5_string)
        (implicit 3 or_address)
        (* Everybody uses this as explicit, contrary to x509 (?) *)
        (explicit 4 Name.name)
        (implicit 5 edi_party_name))
      (choice3
        (implicit 6 ia5_string)
        (implicit 7 octet_string)
        (implicit 8 oid))
end

module Algorithm = struct

  (* This type really conflates three things: the set of pk algos that describe
   * the public key, the set of hashes, and the set of hash+pk algo combinations
   * that describe digests. The three are conflated because they are generated by
   * the same ASN grammar, AlgorithmIdentifier, to keep things close to the
   * standards.
   *
   * It's expected that downstream code with pick a subset and add a catch-all
   * that handles unsupported algos anyway.
   *)

  type t =

    (* pk algos *)
    (* any more? is the universe big enough? ramsey's theorem for pk cyphers? *)
    | RSA
    | EC_pub of OID.t (* should translate the oid too *)

    (* sig algos *)
    | MD2_RSA
    | MD4_RSA
    | MD5_RSA
    | RIPEMD160_RSA
    | SHA1_RSA
    | SHA256_RSA
    | SHA384_RSA
    | SHA512_RSA
    | SHA224_RSA
    | ECDSA_SHA1
    | ECDSA_SHA224
    | ECDSA_SHA256
    | ECDSA_SHA384
    | ECDSA_SHA512

    (* digest algorithms *)
    | MD2
    | MD4
    | MD5
    | SHA1
    | SHA256
    | SHA384
    | SHA512
    | SHA224
    | SHA512_224
    | SHA512_256

  (* XXX
   *
   * PKCS1/RFC5280 allows params to be `ANY', depending on the algorithm.  I don't
   * know of one that uses anything other than NULL and OID, however, so we accept
   * only that.
   *)

  let identifier =
    let open Registry in

    let unit = Some (`C1 ()) in

    let f = function
      | (oid, Some (`C2 oid')) when oid = ANSI_X9_62.ec_pub_key -> EC_pub oid'
      | (oid, _) when oid = PKCS1.rsa_encryption  -> RSA

      | (oid, _) when oid = PKCS1.md2_rsa_encryption       -> MD2_RSA
      | (oid, _) when oid = PKCS1.md4_rsa_encryption       -> MD4_RSA
      | (oid, _) when oid = PKCS1.md5_rsa_encryption       -> MD5_RSA
      | (oid, _) when oid = PKCS1.ripemd160_rsa_encryption -> RIPEMD160_RSA
      | (oid, _) when oid = PKCS1.sha1_rsa_encryption      -> SHA1_RSA
      | (oid, _) when oid = PKCS1.sha256_rsa_encryption    -> SHA256_RSA
      | (oid, _) when oid = PKCS1.sha384_rsa_encryption    -> SHA384_RSA
      | (oid, _) when oid = PKCS1.sha512_rsa_encryption    -> SHA512_RSA
      | (oid, _) when oid = PKCS1.sha224_rsa_encryption    -> SHA224_RSA

      | (oid, _) when oid = ANSI_X9_62.ecdsa_sha1   -> ECDSA_SHA1
      | (oid, _) when oid = ANSI_X9_62.ecdsa_sha224 -> ECDSA_SHA224
      | (oid, _) when oid = ANSI_X9_62.ecdsa_sha256 -> ECDSA_SHA256
      | (oid, _) when oid = ANSI_X9_62.ecdsa_sha384 -> ECDSA_SHA384
      | (oid, _) when oid = ANSI_X9_62.ecdsa_sha512 -> ECDSA_SHA512

      | (oid, _) when oid = md2        -> MD2
      | (oid, _) when oid = md4        -> MD4
      | (oid, _) when oid = md5        -> MD5
      | (oid, _) when oid = sha1       -> SHA1
      | (oid, _) when oid = sha256     -> SHA256
      | (oid, _) when oid = sha384     -> SHA384
      | (oid, _) when oid = sha512     -> SHA512
      | (oid, _) when oid = sha224     -> SHA224
      | (oid, _) when oid = sha512_224 -> SHA512_224
      | (oid, _) when oid = sha512_256 -> SHA512_256

      | (oid, _) -> parse_error_oid "unexpected params or unknown algorithm" oid

    and g = function
      | EC_pub id     -> (ANSI_X9_62.ec_pub_key, Some (`C2 id))
      | RSA           -> (PKCS1.rsa_encryption           , unit)
      | MD2_RSA       -> (PKCS1.md2_rsa_encryption       , unit)
      | MD4_RSA       -> (PKCS1.md4_rsa_encryption       , unit)
      | MD5_RSA       -> (PKCS1.md5_rsa_encryption       , unit)
      | RIPEMD160_RSA -> (PKCS1.ripemd160_rsa_encryption , unit)
      | SHA1_RSA      -> (PKCS1.sha1_rsa_encryption      , unit)
      | SHA256_RSA    -> (PKCS1.sha256_rsa_encryption    , unit)
      | SHA384_RSA    -> (PKCS1.sha384_rsa_encryption    , unit)
      | SHA512_RSA    -> (PKCS1.sha512_rsa_encryption    , unit)
      | SHA224_RSA    -> (PKCS1.sha224_rsa_encryption    , unit)
      | ECDSA_SHA1    -> (ANSI_X9_62.ecdsa_sha1          , unit)
      | ECDSA_SHA224  -> (ANSI_X9_62.ecdsa_sha224        , unit)
      | ECDSA_SHA256  -> (ANSI_X9_62.ecdsa_sha256        , unit)
      | ECDSA_SHA384  -> (ANSI_X9_62.ecdsa_sha384        , unit)
      | ECDSA_SHA512  -> (ANSI_X9_62.ecdsa_sha512        , unit)
      | MD2           -> (md2                            , unit)
      | MD4           -> (md4                            , unit)
      | MD5           -> (md5                            , unit)
      | SHA1          -> (sha1                           , unit)
      | SHA256        -> (sha256                         , unit)
      | SHA384        -> (sha384                         , unit)
      | SHA512        -> (sha512                         , unit)
      | SHA224        -> (sha224                         , unit)
      | SHA512_224    -> (sha512_224                     , unit)
      | SHA512_256    -> (sha512_256                     , unit)
    in

    map f g @@
    sequence2
      (required ~label:"algorithm" oid)
      (optional ~label:"params"
        (choice2 null oid))

end

module Extension = struct

  module ID = Registry.Cert_extn

  type gen_names = General_name.t list

  let gen_names = sequence_of General_name.general_name

  type key_usage =
    | Digital_signature
    | Content_commitment
    | Key_encipherment
    | Data_encipherment
    | Key_agreement
    | Key_cert_sign
    | CRL_sign
    | Encipher_only
    | Decipher_only

  let key_usage = flags [
      0, Digital_signature
    ; 1, Content_commitment
    ; 2, Key_encipherment
    ; 3, Data_encipherment
    ; 4, Key_agreement
    ; 5, Key_cert_sign
    ; 6, CRL_sign
    ; 7, Encipher_only
    ; 8, Decipher_only
    ]

  type extended_key_usage =
    | Any
    | Server_auth
    | Client_auth
    | Code_signing
    | Email_protection
    | Ipsec_end
    | Ipsec_tunnel
    | Ipsec_user
    | Time_stamping
    | Ocsp_signing
    | Other of OID.t

  let ext_key_usage =
    let open ID.Extended_usage in
    let f = function
      | oid when oid = any              -> Any
      | oid when oid = server_auth      -> Server_auth
      | oid when oid = client_auth      -> Client_auth
      | oid when oid = code_signing     -> Code_signing
      | oid when oid = email_protection -> Email_protection
      | oid when oid = ipsec_end_system -> Ipsec_end
      | oid when oid = ipsec_tunnel     -> Ipsec_tunnel
      | oid when oid = ipsec_user       -> Ipsec_user
      | oid when oid = time_stamping    -> Time_stamping
      | oid when oid = ocsp_signing     -> Ocsp_signing
      | oid                             -> Other oid
    and g = function
      | Any              -> any
      | Server_auth      -> server_auth
      | Client_auth      -> client_auth
      | Code_signing     -> code_signing
      | Email_protection -> email_protection
      | Ipsec_end        -> ipsec_end_system
      | Ipsec_tunnel     -> ipsec_tunnel
      | Ipsec_user       -> ipsec_user
      | Time_stamping    -> time_stamping
      | Ocsp_signing     -> ocsp_signing
      | Other oid        -> oid
    in
    map (List.map f) (List.map g) @@ sequence_of oid

  let basic_constraints =
    map (fun (a, b) -> (def  false a, b))
        (fun (a, b) -> (def' false a, b))
    @@
    sequence2
      (optional ~label:"cA"      bool)
      (optional ~label:"pathLen" int)

  type authority_key_id = Cstruct.t option * gen_names * Num.num option

  let authority_key_id =
    map (fun (a, b, c) -> (a, def  [] b, c))
        (fun (a, b, c) -> (a, def' [] b, c))
    @@
    sequence3
      (optional ~label:"keyIdentifier"  @@ implicit 0 octet_string)
      (optional ~label:"authCertIssuer" @@ implicit 1 gen_names)
      (optional ~label:"authCertSN"     @@ implicit 2 integer)

  type priv_key_usage_period =
    | Interval   of time * time
    | Not_after  of time
    | Not_before of time

  let priv_key_usage_period =
    let f = function
      | (Some t1, Some t2) -> Interval (t1, t2)
      | (Some t1, None   ) -> Not_before t1
      | (None   , Some t2) -> Not_after  t2
      | _                  -> parse_error "empty PrivateKeyUsagePeriod"
    and g = function
      | Interval (t1, t2) -> (Some t1, Some t2)
      | Not_before t1     -> (Some t1, None   )
      | Not_after  t2     -> (None   , Some t2) in
    map f g @@
    sequence2
      (optional ~label:"notBefore" @@ implicit 0 generalized_time)
      (optional ~label:"notAfter"  @@ implicit 1 generalized_time)


  type name_constraint = (General_name.t * int * int option) list
  type name_constraints = name_constraint * name_constraint

  let name_constraints =
    let subtree =
      map (fun (base, min, max) -> (base, def  0 min, max))
          (fun (base, min, max) -> (base, def' 0 min, max))
      @@
      sequence3
        (required ~label:"base"       General_name.general_name)
        (optional ~label:"minimum" @@ implicit 0 int)
        (optional ~label:"maximum" @@ implicit 1 int)
    in
    map (fun (a, b) -> (def  [] a, def  [] b))
        (fun (a, b) -> (def' [] a, def' [] b))
    @@
    sequence2
      (optional ~label:"permittedSubtrees" @@ implicit 0 (sequence_of subtree))
      (optional ~label:"excludedSubtrees"  @@ implicit 1 (sequence_of subtree))


    type cert_policies = [ `Any | `Something of oid ] list

    let cert_policies =
      let open ID.Cert_policy in
      let qualifier_info =
        map (function | (oid, `C1 s) when oid = cps     -> s
                      | (oid, `C2 s) when oid = unotice -> s
                      | _ -> parse_error "bad policy qualifier")
            (function s -> (cps, `C1 s))
        @@
        sequence2
          (required ~label:"qualifierId" oid)
          (required ~label:"qualifier"
            (choice2
              ia5_string
              @@
              map (function (_, Some s) -> s | _ -> "#(BLAH BLAH)")
                  (fun s -> (None, Some s))
              (sequence2
                (optional ~label:"noticeRef"
                  (sequence2
                    (required ~label:"organization" display_text)
                    (required ~label:"numbers"      (sequence_of integer))))
                (optional ~label:"explicitText" display_text))))
      in
      (* "Optional qualifiers, which MAY be present, are not expected to change
       * the definition of the policy."
       * Hence, we just drop them.  *)
      sequence_of @@
        map (function | (oid, _) when oid = any_policy -> `Any
                      | (oid, _)                       -> `Something oid)
            (function | `Any           -> (any_policy, None)
                      | `Something oid -> (oid, None))
        @@
        sequence2
          (required ~label:"policyIdentifier" oid)
          (optional ~label:"policyQualifiers" (sequence_of qualifier_info))


  type t =
    | Unsupported       of OID.t * Cstruct.t
    | Subject_alt_name  of gen_names
    | Authority_key_id  of authority_key_id
    | Subject_key_id    of Cstruct.t
    | Issuer_alt_name   of gen_names
    | Key_usage         of key_usage list
    | Ext_key_usage     of extended_key_usage list
    | Basic_constraints of (bool * int option)
    | Priv_key_period   of priv_key_usage_period
    | Name_constraints  of name_constraints
    | Policies          of cert_policies


  let gen_names_of_cs, gen_names_to_cs       = project_exn gen_names
  and auth_key_id_of_cs, auth_key_id_to_cs   = project_exn authority_key_id
  and subj_key_id_of_cs, subj_key_id_to_cs   = project_exn octet_string
  and key_usage_of_cs, key_usage_to_cs       = project_exn key_usage
  and e_key_usage_of_cs, e_key_usage_to_cs   = project_exn ext_key_usage
  and basic_constr_of_cs, basic_constr_to_cs = project_exn basic_constraints
  and pr_key_peri_of_cs, pr_key_peri_to_cs   = project_exn priv_key_usage_period
  and name_con_of_cs, name_con_to_cs         = project_exn name_constraints
  and cert_pol_of_cs, cert_pol_to_cs         = project_exn cert_policies

  (* XXX 4.2.1.4. - cert policies! ( and other x509 extensions ) *)

  let reparse_extension_exn = function
    | (oid, cs) when oid = ID.subject_alternative_name ->
        Subject_alt_name (gen_names_of_cs cs)

    | (oid, cs) when oid = ID.issuer_alternative_name ->
        Issuer_alt_name (gen_names_of_cs cs)

    | (oid, cs) when oid = ID.authority_key_identifier ->
        Authority_key_id (auth_key_id_of_cs cs)

    | (oid, cs) when oid = ID.subject_key_identifier ->
        Subject_key_id (subj_key_id_of_cs cs)

    | (oid, cs) when oid = ID.key_usage ->
        Key_usage (key_usage_of_cs cs)

    | (oid, cs) when oid = ID.basic_constraints ->
        Basic_constraints (basic_constr_of_cs cs)

    | (oid, cs) when oid = ID.extended_key_usage ->
        Ext_key_usage (e_key_usage_of_cs cs)

    | (oid, cs) when oid = ID.private_key_usage_period ->
        Priv_key_period (pr_key_peri_of_cs cs)

    | (oid, cs) when oid = ID.name_constraints ->
        Name_constraints (name_con_of_cs cs)

    | (oid, cs) when oid = ID.certificate_policies_2 ->
        Policies (cert_pol_of_cs cs)

    | (oid, cs) -> Unsupported (oid, cs)

  let unparse_extension = function
    | Subject_alt_name  x -> (ID.subject_alternative_name, gen_names_to_cs    x)
    | Issuer_alt_name   x -> (ID.issuer_alternative_name , gen_names_to_cs    x)
    | Authority_key_id  x -> (ID.authority_key_identifier, auth_key_id_to_cs  x)
    | Subject_key_id    x -> (ID.subject_key_identifier  , subj_key_id_to_cs  x)
    | Key_usage         x -> (ID.key_usage               , key_usage_to_cs    x)
    | Basic_constraints x -> (ID.basic_constraints       , basic_constr_to_cs x)
    | Ext_key_usage     x -> (ID.extended_key_usage      , e_key_usage_to_cs  x)
    | Priv_key_period   x -> (ID.private_key_usage_period, pr_key_peri_to_cs  x)
    | Name_constraints  x -> (ID.name_constraints        , name_con_to_cs     x)
    | Policies          x -> (ID.certificate_policies_2  , cert_pol_to_cs     x)
    | Unsupported (oid, cs) -> (oid, cs)

  let extensions_der =
    let extension =
      let f (oid, b, cs) =
        (def false b, reparse_extension_exn (oid, cs))
      and g (b, ext) =
        let (oid, cs) = unparse_extension ext in (oid, def' false b, cs)
      in
      map f g @@
      sequence3
        (required ~label:"id"       oid)
        (optional ~label:"critical" bool) (* default false *)
        (required ~label:"value"    octet_string)
    in
    sequence_of extension

end

module PK = struct

  open Nocrypto

  (* RSA *)

  let other_prime_infos =
    sequence_of @@
      (sequence3
        (required ~label:"prime"       big_natural)
        (required ~label:"exponent"    big_natural)
        (required ~label:"coefficient" big_natural))

  let rsa_private_key =

    (* XXX ditch big_natural parser, use zarith for asn integer *)
    let f (_, (n, (e, (d, (p, (q, (dp, (dq, (q', _))))))))) =
      Cstruct.(RSA.priv ~e:(of_string e) ~d:(of_string d) ~n:(of_string n)
                        ~p:(of_string p) ~q:(of_string q)
                        ~dp:(of_string dp) ~dq:(of_string dq) ~q':(of_string q'))

    and g priv = assert false (* XXX export from nocrypto *) in (* v.0 *)

    map f g @@
    sequence @@
        (required ~label:"version"         int)
      @ (required ~label:"modulus"         big_natural)  (* n    *)
      @ (required ~label:"publicExponent"  big_natural)  (* e    *)
      @ (required ~label:"privateExponent" big_natural)  (* d    *)
      @ (required ~label:"prime1"          big_natural)  (* p    *)
      @ (required ~label:"prime2"          big_natural)  (* q    *)
      @ (required ~label:"exponent1"       big_natural)  (* dp   *)
      @ (required ~label:"exponent2"       big_natural)  (* dq   *)
      @ (required ~label:"coefficient"     big_natural)  (* qinv *)
     -@ (optional ~label:"otherPrimeInfos" other_prime_infos)


  let rsa_public_key =

    (* XXX ditch big_natural parser, use zarith for asn integer *)
    let f (n, e) = RSA.pub ~n:(Cstruct.of_string n) ~e:(Cstruct.of_string e)
    and g pub = assert false (* XXX export from nocrypto *) in

    map f g @@
    sequence2
      (required ~label:"modulus"        big_natural)
      (required ~label:"publicExponent" big_natural)

  (* For outside uses. *)
  let (rsa_private_of_cstruct, rsa_private_to_cstruct) =
    projections der rsa_private_key
  and (rsa_public_of_cstruct, rsa_public_to_cstruct) =
    projections der rsa_public_key

  (* ECs go here *)
  (* ... *)

  type t =
    | RSA    of RSA.pub
    | EC_pub of OID.t

  let rsa_pub_of_cs, rsa_pub_to_cs = project_exn rsa_public_key

  let reparse_pk = function
    | (Algorithm.RSA      , cs) -> RSA (rsa_pub_of_cs cs)
    | (Algorithm.EC_pub id, cs) -> EC_pub id
    | _ -> parse_error "unknown public key algorithm"

  let unparse_pk = function
    | RSA pk    -> (Algorithm.RSA, rsa_pub_to_cs pk)
    | EC_pub id -> (Algorithm.EC_pub id, Cstruct.create 0)

  let pk_info_der =
    map reparse_pk unparse_pk @@
    sequence2
      (required ~label:"algorithm" Algorithm.identifier)
      (required ~label:"subjectPK" bit_string')

end


(*
 * X509 certs
 *)


type tBSCertificate = {
  version    : [ `V1 | `V2 | `V3 ] ;
  serial     : Num.num ;
  signature  : Algorithm.t ;
  issuer     : Name.dn ;
  validity   : time * time ;
  subject    : Name.dn ;
  pk_info    : PK.t ;
  issuer_id  : bits option ;
  subject_id : bits option ;
  extensions : (bool * Extension.t) list
}

type certificate = {
  tbs_cert       : tBSCertificate ;
  signature_algo : Algorithm.t ;
  signature_val  : bits
}


(* XXX really default other versions to V1 or bail out? *)
let version =
  map (function 2 -> `V2 | 3 -> `V3 | _ -> `V1)
      (function `V2 -> 2 | `V3 -> 3 | _ -> 1)
  int

let certificate_sn = integer

let time =
  map (function `C1 t -> t | `C2 t -> t) (fun t -> `C2 t)
      (choice2 utc_time generalized_time)

let validity =
  sequence2
    (required ~label:"not before" time)
    (required ~label:"not after"  time)

let unique_identifier = bit_string'

let tBSCertificate =
  let f = fun (a, (b, (c, (d, (e, (f, (g, (h, (i, j))))))))) ->
    let extn = match j with None -> [] | Some xs -> xs
    in
    { version    = def `V1 a ; serial     = b ;
      signature  = c         ; issuer     = d ;
      validity   = e         ; subject    = f ;
      pk_info    = g         ; issuer_id  = h ;
      subject_id = i         ; extensions = extn }

  and g = fun
    { version    = a ; serial     = b ;
      signature  = c ; issuer     = d ;
      validity   = e ; subject    = f ;
      pk_info    = g ; issuer_id  = h ;
      subject_id = i ; extensions = j } ->
    let extn = match j with [] -> None | xs -> Some xs
    in
    (def' `V1 a, (b, (c, (d, (e, (f, (g, (h, (i, extn)))))))))
  in

  map f g @@
  sequence @@
      (optional ~label:"version"       @@ explicit 0 version) (* default v1 *)
    @ (required ~label:"serialNumber"  @@ certificate_sn)
    @ (required ~label:"signature"     @@ Algorithm.identifier)
    @ (required ~label:"issuer"        @@ Name.name)
    @ (required ~label:"validity"      @@ validity)
    @ (required ~label:"subject"       @@ Name.name)
    @ (required ~label:"subjectPKInfo" @@ PK.pk_info_der)
      (* if present, version is v2 or v3 *)
    @ (optional ~label:"issuerUID"     @@ implicit 1 unique_identifier)
      (* if present, version is v2 or v3 *)
    @ (optional ~label:"subjectUID"    @@ implicit 2 unique_identifier)
      (* v3 if present *)
   -@ (optional ~label:"extensions"    @@ explicit 3 Extension.extensions_der)

let (tbs_certificate_of_cstruct, tbs_certificate_to_cstruct) =
  projections der tBSCertificate

let certificate =

  let f (a, b, c) =
    if a.signature <> b then
      parse_error "signatureAlgorithm != tbsCertificate.signature"
    else
      { tbs_cert = a; signature_algo = b; signature_val = c }

  and g { tbs_cert = a; signature_algo = b; signature_val = c } = (a, b, c) in

  map f g @@
  sequence3
    (required ~label:"tbsCertificate"     tBSCertificate)
    (required ~label:"signatureAlgorithm" Algorithm.identifier)
    (required ~label:"signatureValue"     bit_string')

let (certificate_of_cstruct, certificate_to_cstruct) =
  projections der certificate


let pkcs1_digest_info =
  sequence2
    (required ~label:"digestAlgorithm" Algorithm.identifier)
    (required ~label:"digest"          octet_string)

let (pkcs1_digest_info_of_cstruct, pkcs1_digest_info_to_cstruct) =
  projections der pkcs1_digest_info

(* A bit of accessors for tree-diving. *)
(*
 * XXX We re-traverse the list over 9000 times. Abstract out the extensions in a
 * cert into sth more efficient at the cost of losing the printer during
 * debugging?
 *)
let  extn_subject_alt_name
   , extn_issuer_alt_name
   , extn_authority_key_id
   , extn_subject_key_id
   , extn_key_usage
   , extn_ext_key_usage
   , extn_basic_constr
   , extn_priv_key_period
   , extn_name_constraints
   , extn_policies
=
  let f pred cert =
    Utils.map_find cert.tbs_cert.extensions
      ~f:(fun (crit, ext) ->
            match pred ext with None -> None | Some x -> Some (crit, x))
  in
  let open Extension in
  (f @@ function Subject_alt_name  _ as x -> Some x | _ -> None),
  (f @@ function Issuer_alt_name   _ as x -> Some x | _ -> None),
  (f @@ function Authority_key_id  _ as x -> Some x | _ -> None),
  (f @@ function Subject_key_id    _ as x -> Some x | _ -> None),
  (f @@ function Key_usage         _ as x -> Some x | _ -> None),
  (f @@ function Ext_key_usage     _ as x -> Some x | _ -> None),
  (f @@ function Basic_constraints _ as x -> Some x | _ -> None),
  (f @@ function Priv_key_period   _ as x -> Some x | _ -> None),
  (f @@ function Name_constraints  _ as x -> Some x | _ -> None),
  (f @@ function Policies          _ as x -> Some x | _ -> None)
