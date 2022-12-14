module W = Eio.Buf_write

let src = Logs.Src.create "mock-socket" ~doc:"Test socket"
module Log = (val Logs.src_log src : Logs.LOG)

type transmit_amount = [`Bytes of int | `Drain]

type socket = < Eio.Flow.two_way; transmit : transmit_amount -> unit >

let create ~to_peer ~from_peer label =
  object
    inherit Eio.Flow.two_way

    val output_sizes = Eio.Stream.create max_int

    method transmit x =
      Eio.Stream.add output_sizes x

    method copy src =
      try
        while true do
          let rec write = function
            | 0 -> ()
            | size ->
              let buf = Cstruct.create size in
              let got = Eio.Flow.single_read src buf in
              W.cstruct to_peer (Cstruct.sub buf 0 got);
              Log.info (fun f -> f "%s: wrote %d bytes to network" label got);
              write (size - got)
          in
          match Eio.Stream.take output_sizes with
          | `Drain -> Eio.Stream.add output_sizes `Drain; write 4096
          | `Bytes n -> write n
        done
      with End_of_file -> ()

    method read_into buf =
      let batch = W.await_batch from_peer in
      let got, _ = Cstruct.fillv ~src:batch ~dst:buf in
      Log.info (fun f -> f "%s: read %d bytes from network" label got);
      W.shift from_peer got;
      got

    method shutdown = function
      | `Send -> 
        Log.info (fun f -> f "%s: close writer" label);
        W.close to_peer
      | _ -> failwith "Not implemented"
  end

let create_pair () =
  let to_a = W.create 100 in
  let to_b = W.create 100 in
  let a = create ~from_peer:to_a ~to_peer:to_b "client" in
  let b = create ~from_peer:to_b ~to_peer:to_a "server" in
  a, b
