## TLS - Transport Layer Security purely in OCaml

%%VERSION%%

Transport Layer Security (TLS) is probably the most widely deployed security
protocol on the Internet. It provides communication privacy to prevent
eavesdropping, tampering, and message forgery. Furthermore, it optionally
provides authentication of the involved endpoints. TLS is commonly deployed for
securing web services ([HTTPS](http://tools.ietf.org/html/rfc2818)), emails,
virtual private networks, and wireless networks.

TLS uses asymmetric cryptography to exchange a symmetric key, and optionally
authenticate (using X.509) either or both endpoints. It provides algorithmic
agility, which means that the key exchange method, symmetric encryption
algorithm, and hash algorithm are negotiated.

Read our [Usenix Security 2015 paper](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/kaloper-mersinjak) for further details.

## Documentation

[API documentation](https://mirleft.github.io/ocaml-tls/doc)

## Installation

`opam install tls` will install this library.

You can also build this locally by conducting the steps:

```bash
opam install --deps-only -t . # or a named package instead of `.` - i.e. ./tls-lwt.opam
dune build --profile=release # you can also put a package list here, i.e. tls,tls-lwt -- you can also use `@all` target to compile examples as well
```

## Usage

The core of `ocaml-tls` (the opam package `tls`, available in the `lib`
subdirectory) is an library independent of schedulers and does not perform any
I/O operations. The library is designed so that a `Tls.Engine.state` state
informs you of when to write and when to feed more data. It does not use
mutation and is in a value-passing style (so, read data and state is the input,
and data to be sent or presented to the upper layer, and state is the output).

There are therefore `ocaml-tls` derivations with different schedulers that
perform read and write operations. These derivations offer an interface similar
to what an SSL socket (like [ssl][ssl]) can offer.
- [lwt](https://ocsigen.org/lwt/latest/manual/manual): `tls-lwt` proposes to
  initiate a TLS flow with `Lwt_io.{input,output}_channel` from a Unix socket.
  It can also propose an abstract type `Tls_lwt.Unix.t` (which can be created
  from a Unix socket) associated with a `Tls_lwt.Unix` interface similar to a
  Unix socket.
- [miou](https://github.com/robur-coop/miou): `tls-miou-unix` proposes a TLS
  flow via an abstract type `Tls_miou_unix.t` and an interface similar to a Unix
  socket from a `Miou_unix.file_descr` socket.
- [MirageOS](https://mirageos.org): `tls-mirage` proposes a composition
  of a [`Mirage_flow.S`](https://github.com/mirage/mirage-flow/) module to
  obtain a new `Mirage_flow.S` (corresponding to the TLS layer) which uses the
  lwt scheduler.
- [eio](https://github.com/ocaml-multicore/eio): `tls-eio` proposes the creation
  of an _eio flow_ from another _eio flow_.
- [async](https://github.com/janestreet/async): `tls-async` proposes a TLS flow
  via `Async.{Reader,Writer}.t` from a `Async.Socket`.

Depending on the scheduler you choose, you should choose one of these
`ocaml-tls` derivations, distributed in the mentioned opam packages (tls-lwt,
tls-mirage, tls-eio, tls-async). Each one takes advantage of what the scheduler
used has to offer.

### Composability

`ocaml-tls` can also be used as it is in order to be able to compose with other
protocols without choosing a scheduler. This is the case, for example, with
[sendmail.starttls][sendmail], which composes the SMTP and TLS protocols. The
user can also be more selective about the use of certificates involved in a TLS
connection, as [albatross][albatross] can offer in its transactions between
clients and the server.

When seen as OCaml values, the critical elements that enable instantiation of a
TLS connection can be very finely controlled.

### Portability

ocaml-tls is currently used for [MirageOS unikernels](https://mirageos.org),
which makes it portable and available on many systems (even the most restricted
ones such as [Solo5](https://github.com/solo5/solo5) as long as OCaml is
available on them.

[sendmail]: https://github.com/mirage/colombe
[albatross]: https://github.com/robur-coop/albatross
[ssl]: https://github.com/savonet/ocaml-ssl
