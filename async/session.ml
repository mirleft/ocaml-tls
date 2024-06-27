open! Core
open! Async

module Fd = struct
  type t = Reader.t * Writer.t

  let read (reader, (_ : Writer.t)) buf =
    Deferred.Or_error.try_with (fun () -> Reader.read reader buf)
  ;;

  let write ((_ : Reader.t), writer) buf =
    Deferred.Or_error.try_with (fun () ->
      Writer.write writer buf;
      Writer.flushed writer)
  ;;

  let rec write_full fd buf =
    let open Deferred.Or_error.Let_syntax in
    match String.length buf with
    | 0 -> return ()
    | len ->
      let%bind () = write fd buf in
      write_full fd (String.sub buf ~pos:len ~len:(String.length buf - len))
  ;;
end

include Io.Make (Fd)
