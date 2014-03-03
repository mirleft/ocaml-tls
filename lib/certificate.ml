open Core
open Asn_grammars
open Packet

type certificate_verification_result = [
  | `Fail of alert_type
  | `Ok
]

let validate_certificate : certificate -> certificate_verification_result =
  fun c ->
    `Ok

let validate_certificates : certificate list -> certificate_verification_result =
  fun cs ->
    let rec go = function
      | []    -> `Ok
      | c::cs ->
         match validate_certificate c with
         | `Ok   -> go cs
         | `Fail x -> `Fail x
    in
    go cs
