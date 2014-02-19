
open Asn

type bits = bool array

let def  x = function None -> x | Some y -> y
let def' x = fun y -> if y = x then None else Some y

(*
 * X509 certs
 *)

type tBSCertificate = {
  version    : [ `V1 | `V2 | `V3 ] ;
  serial     : int ;
  signature  : oid ;
  issuer     : (oid * string) list list ;
  validity   : time * time ;
  subject    : (oid * string) list list ;
  pk_info    : oid * bits ;
  issuer_id  : bits option ;
  subject_id : bits option ;
  extensions : (oid * bool * bytes) list option
}

type certificate = {
  tbs_cert       : tBSCertificate ;
  signature_algo : oid ;
  signature      : bits
}

let extensions =
  let extension =
    map (fun (oid, b, v) -> (oid, def  false b, v))
        (fun (oid, b, v) -> (oid, def' false b, v)) @@
    sequence3
      (required ~label:"id"       oid)
      (optional ~label:"critical" bool) (* default false *)
      (required ~label:"value"    octet_string)
  in
  sequence_of extension

let directory_name =
  map (function | `C1 s -> s | `C2 s -> s | `C3 s -> s
                | `C4 s -> s | `C5 s -> s | `C6 s -> s)
      (function s -> `C1 s)
  @@
  choice6
    printable_string utf8_string
    (* The following three could probably be ommited.
      * See rfc5280 section 4.1.2.4. *)
    teletex_string universal_string bmp_string
    (* is this standard? *)
    ia5_string

let name =
  let attribute_tv =
   sequence2
      (required ~label:"attr type"  oid)
      (* This is ANY according to rfc5280. *)
      (required ~label:"attr value" directory_name) in
  let rd_name      = set_of attribute_tv in
  let rdn_sequence = sequence_of rd_name in
  rdn_sequence (* A vacuous choice, in the standard. *)

let algorithmIdentifier =
  map (fun (oid, _) -> oid) (fun oid -> (oid, None))
  @@
  sequence2
    (required ~label:"algorithm" oid)
    (* This is ANY according to rfc5280 *)
    (optional ~label:"params"    null)

let version =
  map (function `I 2 -> `V2 | `I 3 -> `V3 | _ -> `V1)
      (function `V2 -> `I 2 | `V3 -> `I 3 | _ -> `I 1)
  int

let certificateSerialNumber =
  map (function `I sn -> sn | _ -> -1) (fun sn -> `I sn) int

let time =
  map (function `C1 t -> t | `C2 t -> t) (fun t -> `C2 t)
      (choice2 utc_time generalized_time)

let validity =
  sequence2
    (required ~label:"not before" time)
    (required ~label:"not after"  time)

let subjectPublicKeyInfo =
  sequence2
    (required ~label:"algorithm" algorithmIdentifier)
    (required ~label:"subjectPK" bit_string)

let uniqueIdentifier = bit_string

let tBSCertificate =
  let f = fun (a, (b, (c, (d, (e, (f, (g, (h, (i, j))))))))) ->
    { version    = def `V1 a ; serial     = b ;
      signature  = c         ; issuer     = d ;
      validity   = e         ; subject    = f ;
      pk_info    = g         ; issuer_id  = h ;
      subject_id = i         ; extensions = j }

  and g = fun
    { version    = a ; serial     = b ;
      signature  = c ; issuer     = d ;
      validity   = e ; subject    = f ;
      pk_info    = g ; issuer_id  = h ;
      subject_id = i ; extensions = j } ->
    (def' `V1 a, (b, (c, (d, (e, (f, (g, (h, (i, j)))))))))
  in

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
   -@ (optional ~label:"extensions"    @@ explicit 3 extensions)

let certificate =

  let f (a, b, c) =
    { tbs_cert = a ; signature_algo = b ; signature = c }

  and g { tbs_cert = a ; signature_algo = b ; signature = c } =
    (a, b, c) in

  map f g @@
  sequence3
    (required ~label:"tbsCertificate"     tBSCertificate)
    (required ~label:"signatureAlgorithm" algorithmIdentifier)
    (required ~label:"signatureValue"     bit_string)


let cert_ber = codec ber certificate
let certificate_of_bytes = decode cert_ber
and certificate_to_bytes = encode cert_ber


(*
 * RSA pk
 *)

type rsa_private_key = {
  modulus           : integer;
  public_exponent   : integer;
  private_exponent  : integer;
  prime1            : integer;
  prime2            : integer;
  exponent1         : integer;
  exponent2         : integer;
  coefficient       : integer;
  other_prime_infos : (integer * integer * integer) list
}

let other_prime_infos =
  sequence_of @@
    (sequence3
      (required ~label:"prime"       int)
      (required ~label:"exponent"    int)
      (required ~label:"coefficient" int))

let rsa_private_key =

  let f = fun (_, (b, (c, (d, (e, (f, (g, (h, (i, j))))))))) ->
    { modulus           = b        ; public_exponent = c ;
      private_exponent  = d        ; prime1          = e ;
      prime2            = f        ; exponent1       = g ;
      exponent2         = h        ; coefficient     = i ;
      other_prime_infos = def [] j ; }

  and g = fun 
    { modulus            = b ; public_exponent = c ;
      private_exponent   = d ; prime1          = e ;
      prime2             = f ; exponent1       = g ;
      exponent2          = h ; coefficient     = i ;
      other_prime_infos  = j ; } ->
    (`I 0, (b, (c, (d, (e, (f, (g, (h, (i, def' [] j)))))))))
  in

  map f g @@
  sequence @@
      (required ~label:"version"           int)
    @ (required ~label:"modulus"           int)
    @ (required ~label:"publicExponent"    int)
    @ (required ~label:"privateExponent"   int)
    @ (required ~label:"prime1"            int)
    @ (required ~label:"prime2"            int)
    @ (required ~label:"exponent1"         int)
    @ (required ~label:"exponent2"         int)
    @ (required ~label:"coefficient"       int)
   -@ (optional ~label:"otherPrimeInfos"   other_prime_infos)


let rsa_private_key_ber = codec ber certificate
let rsa_private_key_of_bytes = decode rsa_private_key_ber
and rsa_private_key_to_bytes = encode rsa_private_key_ber
