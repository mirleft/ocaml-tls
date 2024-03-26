open Eio.Std

module W = Eio.Buf_write

let src = Logs.Src.create "mock-socket" ~doc:"Test socket"
module Log = (val Logs.src_log src : Logs.LOG)

type transmit_amount = [`Bytes of int | `Drain]

type ty = [`Mock_tls | Eio.Flow.two_way_ty | Eio.Resource.close_ty]
type t = ty r

let rec takev len = function
  | [] -> []
  | x :: xs ->
    if len = 0 then []
    else if Cstruct.length x >= len then [Cstruct.sub x 0 len]
    else x :: takev (len - Cstruct.length x) xs

module Impl = struct
  type t = {
    to_peer : W.t;
    from_peer : W.t;
    label : string;
    output_sizes : transmit_amount Eio.Stream.t;
  }

  let create ~to_peer ~from_peer label = {
    to_peer;
    from_peer;
    label;
    output_sizes = Eio.Stream.create max_int;
  }

  let transmit t x =
    Eio.Stream.add t.output_sizes x

  let single_write t bufs =
    let size =
      match Eio.Stream.take t.output_sizes with
      | `Drain -> Eio.Stream.add t.output_sizes `Drain; Cstruct.lenv bufs
      | `Bytes size -> size
    in
    let bufs = takev size bufs in
    List.iter (W.cstruct t.to_peer) bufs;
    let len = Cstruct.lenv bufs in
    Log.info (fun f -> f "%s: wrote %d bytes to network" t.label len);
    len

  let copy t ~src = Eio.Flow.Pi.simple_copy ~single_write t ~src

  let single_read t buf =
    let batch = W.await_batch t.from_peer in
    let got, _ = Cstruct.fillv ~src:batch ~dst:buf in
    Log.info (fun f -> f "%s: read %d bytes from network" t.label got);
    W.shift t.from_peer got;
    got

  let shutdown t = function
    | `Send -> 
      Log.info (fun f -> f "%s: close writer" t.label);
      W.close t.to_peer
    | _ -> failwith "Not implemented"

  let close t =
    Log.info (fun f -> f "%s: close connection" t.label)

  let read_methods = []

  type (_, _, _) Eio.Resource.pi += Raw : ('t, 't -> t, ty) Eio.Resource.pi
  let raw (Eio.Resource.T (t, ops)) = Eio.Resource.get ops Raw t
end

let handler =
  Eio.Resource.handler (
    H (Impl.Raw, Fun.id) ::
    H (Eio.Resource.Close, Impl.close) ::
    Eio.Resource.bindings (Eio.Flow.Pi.two_way (module Impl))
  )

let transmit t x =
  let t = Impl.raw t in
  Impl.transmit t x

let create ~from_peer ~to_peer label =
  let t = Impl.create ~from_peer ~to_peer label in
  Eio.Resource.T (t, handler)

let create_pair () =
  let to_a = W.create 100 in
  let to_b = W.create 100 in
  let a = create ~from_peer:to_a ~to_peer:to_b "client" in
  let b = create ~from_peer:to_b ~to_peer:to_a "server" in
  a, b
