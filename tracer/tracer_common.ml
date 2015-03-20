
open Tls

type trace = [
  | `StateIn of State.state
  | `StateOut of State.state
  | `State of State.state
  | `RecordIn of Core.tls_hdr * Cstruct.t
  | `RecordOut of Packet.content_type * Cstruct.t
  | `ApplicationDataIn of Cstruct.t
  | `ApplicationDataOut of Cstruct.t
  | `AlertOut of Core.tls_alert
  | `AlertIn of Core.tls_alert
  | `ChangeCipherSpecIn
  | `ChangeCipherSpecOut
  | `HelloRequest
  | `Failure of Engine.failure
  | `BufIn of Cstruct.t
  | `TimeOut
  | `Eof
] with sexp

let rec find_trace (p : trace -> bool) (xs : trace list) =
  match xs with
  | [] -> None
  | x::xs when p x -> Some x
  | _::xs -> find_trace p xs

