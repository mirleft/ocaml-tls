open Eio.Std

type transmit_amount = [
  | `Bytes of int   (* Send the next n bytes of data *)
  | `Drain          (* Transmit all data immediately from now on *)
]

type t = [`Mock_tls | Eio.Flow.two_way_ty | Eio.Resource.close_ty] r

val create_pair : unit -> t * t
(** Create a pair of sockets [client, server], such that writes to one can be read from the other. *)

val transmit : t -> transmit_amount -> unit
