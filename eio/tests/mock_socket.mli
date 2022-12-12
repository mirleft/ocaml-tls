type transmit_amount = [
  | `Bytes of int   (* Send the next n bytes of data *)
  | `Drain          (* Transmit all data immediately from now on *)
]

type socket = <
  Eio.Flow.two_way;
  transmit : transmit_amount -> unit;
>

val create_pair : unit -> socket * socket
(** Create a pair of sockets [client, server], such that writes to one can be read from the other. *)
