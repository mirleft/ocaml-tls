open Asn

type bits = Cstruct.t

let def  x = function None -> x | Some y -> y
let def' x = fun y -> if y = x then None else Some y

let projections encoding asn =
  let c = codec encoding asn in
  (decode c, encode c)

module ID = struct

  (*
   * Object Identifiers: magic numbers with a tie. Some OIDs also have an MBA.
   *
   * http://www.alvestrand.no/objectid/
   * http://oid-info.com/
   *)

  let usa    = OID.(base 1 2 <| 840)
  let rsadsi = OID.(usa <| 113549)
  let pkcs   = OID.(rsadsi <| 1)

  let md2   = OID.(rsadsi <| 2 <| 2)
  let md5   = OID.(rsadsi <| 2 <| 5)
  let sha1  = OID.(base 1 3 <| 14 <| 3 <| 2 <| 26)
  let sha256, sha384, sha512, sha224, sha512_224, sha512_256 =
    let pre =
      OID.(base 2 16 <| 840 <| 1 <| 101 <| 3 <| 4 <| 2) in
    OID.( pre <| 1, pre <| 2, pre <| 3, pre <| 4, pre <| 5, pre <| 6 )

  module PKCS1 = struct
    let pkcs1 = OID.(pkcs <| 1)

    let rsa_encryption           = OID.(pkcs1 <| 1 )
    and md2_rsa_encryption       = OID.(pkcs1 <| 2 )
    and md4_rsa_encryption       = OID.(pkcs1 <| 3 )
    and md5_rsa_encryption       = OID.(pkcs1 <| 4 )
    and sha1_rsa_encryption      = OID.(pkcs1 <| 5 )
    and ripemd160_rsa_encryption = OID.(pkcs1 <| 6 )
    and rsaes_oaep               = OID.(pkcs1 <| 7 )
    and rsassa_pss               = OID.(pkcs1 <| 10)
    and sha256_rsa_encryption    = OID.(pkcs1 <| 11)
    and sha384_rsa_encryption    = OID.(pkcs1 <| 12)
    and sha512_rsa_encryption    = OID.(pkcs1 <| 13)
    and sha224_rsa_encryption    = OID.(pkcs1 <| 14)
  end

  module PKCS5 = struct
    let pkcs5 = OID.(pkcs <| 5)

    let pbe_md2_des_cbc  = OID.(pkcs5 <| 1 )
    and pbe_md5_des_cbc  = OID.(pkcs5 <| 3 )
    and pbe_md2_rc2_cbc  = OID.(pkcs5 <| 4 )
    and pbe_md5_rc2_cbc  = OID.(pkcs5 <| 6 )
    and pbe_md5_xor      = OID.(pkcs5 <| 9 )
    and pbe_sha1_des_cbc = OID.(pkcs5 <| 10)
    and pbe_sha1_rc2_cbc = OID.(pkcs5 <| 11)
    and pbkdf2           = OID.(pkcs5 <| 12)
    and pbes2            = OID.(pkcs5 <| 13)
    and pbmac1           = OID.(pkcs5 <| 14)
  end

  module PKCS7 = struct
    let pkcs7 = OID.(pkcs <| 7)

    let data                   = OID.(pkcs7 <| 1)
    and signedData             = OID.(pkcs7 <| 2)
    and envelopedData          = OID.(pkcs7 <| 3)
    and signedAndEnvelopedData = OID.(pkcs7 <| 4)
    and digestedData           = OID.(pkcs7 <| 5)
    and encryptedData          = OID.(pkcs7 <| 6)
  end

  module PKCS9 = struct
    let pkcs9 = OID.(pkcs <| 9)

    let email                = OID.(pkcs9 <| 1 )
    and unstructured_name    = OID.(pkcs9 <| 2 )
    and content_type         = OID.(pkcs9 <| 3 )
    and message_digest       = OID.(pkcs9 <| 4 )
    and signing_time         = OID.(pkcs9 <| 5 )
    and challenge_password   = OID.(pkcs9 <| 7 )
    and unstructured_address = OID.(pkcs9 <| 8 )
    and signing_description  = OID.(pkcs9 <| 13)
    and extension_request    = OID.(pkcs9 <| 14)
    and smime_capabilities   = OID.(pkcs9 <| 15)
    and smime_oid_registry   = OID.(pkcs9 <| 16)
    and friendly_name        = OID.(pkcs9 <| 20)
    and cert_types           = OID.(pkcs9 <| 22)
  end

  module X500_at = struct
    let x500_at = OID.(base 2 5 <| 4)

    let object_class                  = OID.(x500_at <| 0 )
    and aliased_entry_name            = OID.(x500_at <| 1 )
    and knowldgeinformation           = OID.(x500_at <| 2 )
    and common_name                   = OID.(x500_at <| 3 )
    and surname                       = OID.(x500_at <| 4 )
    and serial_number                 = OID.(x500_at <| 5 )
    and country_name                  = OID.(x500_at <| 6 )
    and locality_name                 = OID.(x500_at <| 7 )
    and state_or_province_name        = OID.(x500_at <| 8 )
    and street_address                = OID.(x500_at <| 9 )
    and organization_name             = OID.(x500_at <| 10)
    and organizational_unit_name      = OID.(x500_at <| 11)
    and title                         = OID.(x500_at <| 12)
    and description                   = OID.(x500_at <| 13)
    and search_guide                  = OID.(x500_at <| 14)
    and business_category             = OID.(x500_at <| 15)
    and postal_address                = OID.(x500_at <| 16)
    and postal_code                   = OID.(x500_at <| 17)
    and post_office_box               = OID.(x500_at <| 18)
    and physical_delivery_office_name = OID.(x500_at <| 19)
    and telephone_number              = OID.(x500_at <| 20)
    and telex_number                  = OID.(x500_at <| 21)
    and teletex_terminal_identifier   = OID.(x500_at <| 22)
    and facsimile_telephone_number    = OID.(x500_at <| 23)
    and x121_address                  = OID.(x500_at <| 24)
    and internationa_isdn_number      = OID.(x500_at <| 25)
    and registered_address            = OID.(x500_at <| 26)
    and destination_indicator         = OID.(x500_at <| 27)
    and preferred_delivery_method     = OID.(x500_at <| 28)
    and presentation_address          = OID.(x500_at <| 29)
    and supported_application_context = OID.(x500_at <| 30)
    and member                        = OID.(x500_at <| 31)
    and owner                         = OID.(x500_at <| 32)
    and role_occupant                 = OID.(x500_at <| 33)
    and see_also                      = OID.(x500_at <| 34)
    and user_password                 = OID.(x500_at <| 35)
    and user_certificate              = OID.(x500_at <| 36)
    and ca_certificate                = OID.(x500_at <| 37)
    and authority_revocation_list     = OID.(x500_at <| 38)
    and certificate_revocation_list   = OID.(x500_at <| 39)
    and cross_certificate_pair        = OID.(x500_at <| 40)
    and name                          = OID.(x500_at <| 41)
    and given_name                    = OID.(x500_at <| 42)
    and initials                      = OID.(x500_at <| 43)
    and generation_qualifier          = OID.(x500_at <| 44)
    and unique_identifier             = OID.(x500_at <| 45)
    and dn_qualifier                  = OID.(x500_at <| 46)
    and enhanced_search_guide         = OID.(x500_at <| 47)
    and protocol_information          = OID.(x500_at <| 48)
    and distinguished_name            = OID.(x500_at <| 49)
    and unique_member                 = OID.(x500_at <| 50)
    and house_identifier              = OID.(x500_at <| 51)
    and supported_algorithms          = OID.(x500_at <| 52)
    and delta_revocation_list         = OID.(x500_at <| 53)
    and attribute_certificate         = OID.(x500_at <| 58)
    and pseudonym                     = OID.(x500_at <| 65)
  end

end

(*
 * RSA
 *)

(* the no-decode integer, assuming >= 0 and DER. *)
let nat =
  let f cs =
    Cstruct.(to_string @@
              if get_uint8 cs 0 = 0x00 then shift cs 1 else cs)
  and g str =
    assert false in
  map f g @@
    implicit ~cls:`Universal 0x02 octet_string

let other_prime_infos =
  sequence_of @@
    (sequence3
      (required ~label:"prime"       nat)
      (required ~label:"exponent"    nat)
      (required ~label:"coefficient" nat))

let rsa_private_key =
  let open Cryptokit.RSA in

  let f (_, (n, (e, (d, (p, (q, (dp, (dq, (qinv, _))))))))) =
    let size = String.length n * 8 in
    { size; n; e; d; p; q; dp; dq; qinv }

  and g { size; n; e; d; p; q; dp; dq; qinv } =
    (0, (n, (e, (d, (p, (q, (dp, (dq, (qinv, None))))))))) in

  map f g @@
  sequence @@
      (required ~label:"version"         int)
    @ (required ~label:"modulus"         nat)       (* n    *)
    @ (required ~label:"publicExponent"  nat)       (* e    *)
    @ (required ~label:"privateExponent" nat)       (* d    *)
    @ (required ~label:"prime1"          nat)       (* p    *)
    @ (required ~label:"prime2"          nat)       (* q    *)
    @ (required ~label:"exponent1"       nat)       (* dp   *)
    @ (required ~label:"exponent2"       nat)       (* dq   *)
    @ (required ~label:"coefficient"     nat)       (* qinv *)
   -@ (optional ~label:"otherPrimeInfos" other_prime_infos)


let rsa_public_key =
  let open Cryptokit.RSA in

  let f (n, e) =
    let size = String.length n * 8 in
    { size; n; e; d = ""; p = ""; q = ""; dp = ""; dq = ""; qinv = "" }

  and g { n; e } = (n, e) in

  map f g @@
  sequence2
    (required ~label:"modulus"        nat)
    (required ~label:"publicExponent" nat)

let (rsa_private_of_cstruct, rsa_private_to_cstruct) =
  projections der rsa_private_key

let (rsa_public_of_cstruct, rsa_public_to_cstruct) =
  projections der rsa_public_key


(*
 * X509 certs
 *)

type x509_algo = [

type tBSCertificate = {
  version    : [ `V1 | `V2 | `V3 ] ;
  serial     : Num.num ;
  signature  : oid ;
  issuer     : (oid * string) list list ;
  validity   : time * time ;
  subject    : (oid * string) list list ;
  pk_info    : oid * bits ;
  issuer_id  : bits option ;
  subject_id : bits option ;
  extensions : (oid * bool * Cstruct.t) list option
}

type certificate = {
  tbs_cert       : tBSCertificate ;
  signature_algo : oid ;
  signature      : bits
}

(* XXX
 *
 * PKCS1/RFC5280 allows params to be `ANY', depending on the algorithm.  I don't
 * know of one that uses anything other than NULL, however, so we accept only
 * that. Other param types should be encoded as an explicit choice here.
 *
 * In addition, all the algorithms I checked specify their NULL OPTIONAL
 * explicitly, thus we encode it as such. If any algos are encoded without their
 * NULL params, as permitted by the grammar, re-encode won't reconstruct the
 * byte sequence.
 *)
let algorithmIdentifier =
  let f (oid, _) = oid and g oid = (oid, Some ()) in
  map f g @@
  sequence2
    (required ~label:"algorithm" oid)
    (optional ~label:"params"    null)

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

let version =
  map (function 2 -> `V2 | 3 -> `V3 | _ -> `V1)
      (function `V2 -> 2 | `V3 -> 3 | _ -> 1)
  int

let certificateSerialNumber = integer

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
    (required ~label:"subjectPK" bit_string')

let uniqueIdentifier = bit_string'

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

let (tbs_certificate_of_cstruct, tbs_certificate_to_cstruct) =
  projections ber tBSCertificate


let certificate =

  let f (a, b, c) = { tbs_cert = a ; signature_algo = b ; signature = c }

  and g { tbs_cert = a ; signature_algo = b ; signature = c } = (a, b, c) in

  map f g @@
  sequence3
    (required ~label:"tbsCertificate"     tBSCertificate)
    (required ~label:"signatureAlgorithm" algorithmIdentifier)
    (required ~label:"signatureValue"     bit_string')

let (certificate_of_cstruct, certificate_to_cstruct) =
  projections ber certificate

let rsa_public_of_cert cert =
  let oid, bits = cert.tbs_cert.pk_info in
  (* XXX check if oid is actually rsa *)
  match rsa_public_of_cstruct bits with
  | Some (k, _) -> k
  | None -> assert false


let pkcs1_digest_info =
  sequence2
    (required ~label:"digestAlgorithm" algorithmIdentifier)
    (required ~label:"digest"          octet_string)

let (pkcs1_digest_info_of_cstruct, pkcs1_digest_info_to_cstruct) =
  projections der pkcs1_digest_info

