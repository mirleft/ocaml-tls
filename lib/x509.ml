
type time = Asn.Time.t
type oid  = Asn.OID.t
type bits = bool array

type tBSCertificate =
  { version    : [ `V1 | `V2 | `V3 ]
  ;  serial     : int
  ;  signature  : oid
  ;  issuer     : (oid * string) list list
  ;  validity   : time * time
  ;  subject    : (oid * string) list list
  ;  pk_info    : oid * bits
  ;  issuer_id  : bits option
  ;  subject_id : bits option
  ;  extensions : (oid * bool * Asn.bytes) list option
  }

type certificate =
  { tbs_cert       : tBSCertificate
  ; signature_algo : oid
  ; signature      : bits
  }

let extensions =
  let open Asn in
  let extension =
    map (function | (oid, None  , v) -> (oid, false, v)
                  | (oid, Some b, v) -> (oid, b    , v))
        (function | (oid, true , v) -> (oid, Some true, v)
                  | (oid, false, v) -> (oid, None     , v))
    @@
    sequence3
      (required ~label:"id"       oid)
      (optional ~label:"critical" bool) (* default false *)
      (required ~label:"value"    octet_string)
  in
  sequence_of extension

let directory_name =
  let open Asn in
  map (function | `C1 s -> s | `C2 s -> s
                | `C3 s -> s | `C4 s -> s | `C5 s -> s)
      (function s -> `C1 s)
  @@
  choice5
    printable_string
    utf8_string
    (* The following three could probably be ommited.
      * See rfc5280 section 4.1.2.4. *)
    teletex_string
    universal_string
    bmp_string

let name =
  let open Asn in
  let attribute_tv =
   sequence2
      (required ~label:"attr type"  oid)
      (* This is ANY according to rfc5280. *)
      (required ~label:"attr value" directory_name) in
  let rd_name      = set_of attribute_tv in
  let rdn_sequence = sequence_of rd_name in
  rdn_sequence (* A vacuous choice, in the standard. *)


let algorithmIdentifier =
  Asn.(map (fun (oid, _) -> oid) (fun oid -> (oid, None)) @@
        sequence2
          (required ~label:"algorithm" oid)
          (* This is ANY according to rfc5280 *)
          (optional ~label:"params"    null))

let version =
  Asn.(map (fun () -> `V1) (fun _ -> ()) null)
(*   Asn.(map (function `I 2 -> `V2 | `I 3 -> `V3 | _ -> `V1)
           (function `V2 -> `I 2 | `V3 -> `I 3 | _ -> `I 1)
       @@ int) *)

let certificateSerialNumber =
  Asn.(map (fun () -> 1) (fun _ -> ()) null)
(*   Asn.(map (function `I sn -> sn | _ -> -1) (fun sn -> `I sn) int) *)

let time =
  Asn.(map (function `C1 t -> t | `C2 t -> t) (fun t -> `C2 t)
           (choice2 utc_time generalized_time))

let validity =
  Asn.(sequence2
        (required ~label:"not before" time)
        (required ~label:"not after"  time))

let subjectPublicKeyInfo =
  Asn.(sequence2
        (required ~label:"algorithm" algorithmIdentifier)
        (required ~label:"subjectPK" bit_string))

let uniqueIdentifier = Asn.bit_string

let tBSCertificate =
  let f = fun (a, (b, (c, (d, (e, (f, (g, (h, (i, j))))))))) ->
    let v' = match a with None -> `V1 | Some v -> v in
    { version    = v'; serial     = b ;
      signature  = c ; issuer     = d ;
      validity   = e ; subject    = f ;
      pk_info    = g ; issuer_id  = h ;
      subject_id = i ; extensions = j }
  and g = fun
    { version    = v'; serial     = b ;
      signature  = c ; issuer     = d ;
      validity   = e ; subject    = f ;
      pk_info    = g ; issuer_id  = h ;
      subject_id = i ; extensions = j } ->
    let a = match v' with `V1 -> None | v -> Some v in
    (a, (b, (c, (d, (e, (f, (g, (h, (i, j)))))))))
  in
  Asn.(
    map f g @@
    sequence @@
         (optional ~label:"version"       @@ explicit 0 version) (* default v1 *)
       @ (required ~label:"serialNumber"  @@ certificateSerialNumber)
       @ (required ~label:"signature"     @@ algorithmIdentifier)
       @ (required ~label:"issuer"        @@ name)
       @ (required ~label:"validity"      @@ validity)
       @ (required ~label:"subject"       @@ name)
       @ (required ~label:"subjectPKInfo" @@ subjectPublicKeyInfo)
         (* if present, version is v2 or v3 *)
       @ (optional ~label:"issuerUID"     @@ implicit 1 uniqueIdentifier)
         (* if present, version is v2 or v3 *)
       @ (optional ~label:"subjectUID"    @@ implicit 2 uniqueIdentifier)
         (* v3 if present *)
       @
  single (optional ~label:"extensions"    @@ explicit 3 extensions))


let certificate =
  Asn.(
    map (fun (a, b, c) ->
          { tbs_cert = a ; signature_algo = b ; signature = c })
        (fun { tbs_cert = a ; signature_algo = b ; signature = c } ->
          (a, b, c))
    @@
    sequence3
      (required ~label:"tbsCertificate"     tBSCertificate)
      (required ~label:"signatureAlgorithm" algorithmIdentifier)
      (required ~label:"signatureValue"     bit_string))

let codec = Asn.(codec ber) certificate

let certificate_of_bytes = Asn.decode codec
and certificate_to_bytes = Asn.encode codec

type rsa_private_key = {
  modulus : int;
  public_exponent : int;
  private_exponent : int;
  prime1 : int;
  prime2 : int;
  exponent1 : int;
  exponent2 : int;
  coefficient : int
}

(*
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
} *)

let sequence9 a b c d e f g h i =
  Asn.(
    map (fun (a, (b, (c, (d, (e, (f, (g, (h, i)))))))) ->
          (a, b, c, d, e, f, g, h, i))
        (fun (a, b, c, d, e, f, g, h, i) ->
          (a, (b, (c, (d, (e, (f, (g, (h, i)))))))))
        (sequence @@ a @ b @ c @ d @ e @ f @ g @ h @ single i)
  )


let key =
  Asn.(
    map (fun (a, b, c, d, e, f, g, h, i) ->
         { modulus = b ; public_exponent = c ; private_exponent = d ;
           prime1 = e ; prime2 = f ; exponent1 = g ; exponent2 = h ;
           coefficient = i })
        (fun { modulus = b ; public_exponent = c ; private_exponent = d ;
               prime1 = e ; prime2 = f ; exponent1 = g ; exponent2 = h ;
               coefficient = i } ->
         (0, b, c, d, e, f, g, h, i))
    @@
    sequence9
      (required ~label:"version" @@ int)
      (required ~label:"modulus" @@ int)
      (required ~label:"publicExponent" @@ int)
      (required ~label:"privateExponent" @@ int)
      (required ~label:"prime1" @@ int)
      (required ~label:"prime2" @@ int)
      (required ~label:"exponent1" @@ int)
      (required ~label:"exponent2" @@ int)
      (required ~label:"coefficient" @@ int))
