[![Build Status](https://travis-ci.org/mirleft/ocaml-tls.svg?branch=master)](https://travis-ci.org/mirleft/ocaml-tls)

### What is TLS?

Transport Layer Security (TLS) is probably the most widely deployed
security protocol on the Internet. It provides communication privacy
to prevent eavesdropping, tampering, and message forgery. Furthermore,
it optionally provides authentication of the involved endpoints. TLS
is commonly deployed for securing web services
([HTTPS](http://tools.ietf.org/html/rfc2818)), emails, virtual private
networks, and wireless networks.

TLS uses asymmetric cryptography to exchange a symmetric key, and
optionally authenticate (using X.509) either or both endpoints. It
provides algorithmic agility, which means that the key exchange
method, symmetric encryption algorithm, and hash algorithm are
negotiated.

### TLS in OCaml

Our implementation [ocaml-tls](https://github.com/mirleft/ocaml-tls)
is already able to interoperate with existing TLS implementations, and
supports several important TLS extensions such as server name
indication ([RFC4366](https://tools.ietf.org/html/rfc4366), enabling
virtual hosting) and secure renegotiation
([RFC5746](https://tools.ietf.org/html/rfc5746)).

Our [demonstration server](https://tls.openmirage.org/) runs
`ocaml-tls` and renders exchanged TLS messages in nearly real time by
receiving a trace of the TLS session setup. If you encounter any
problems, please give us
[feedback][issues].

`ocaml-tls` and all dependent libraries are available via
[OPAM](https://opam.ocaml.org/packages/tls) (`opam install tls`). The
source is available under a BSD license. We are primarily working
towards completeness of protocol features, such as client
authentication, session resumption, elliptic curve and GCM cipher
suites, and have not yet optimised for performance.

`ocaml-tls` depends on the following independent libraries:
[`ocaml-nocrypto`][ocaml-nocrypto] implements the cryptographic
primitives, [`ocaml-asn1-combinators`][ocaml-asn1-combinators]
provides ASN.1 parsers/unparsers, and [`ocaml-x509`][ocaml-x509]
implements the X509 grammar and certificate validation
([RFC5280](https://tools.ietf.org/html/rfc5280)). `ocaml-tls`
implements TLS (1.0 [RFC2246](https://tools.ietf.org/html/rfc2246),
1.1 [RFC4346](https://tools.ietf.org/html/rfc4346), and 1.2
[RFC5246](https://tools.ietf.org/html/rfc5246)).

We invite the community to audit and run our code, and we are
particularly interested in discussion of our APIs.  Please use the
[mirage-devel mailing
list](http://lists.xenproject.org/archives/html/mirageos-devel/) for
discussions.

**Please be aware that this software is *beta* and is missing external code audits.
It is not yet intended for use in any security critical applications.**

In our [issue tracker][issues] we transparently document known attacks
against TLS and our mitigations ([checked][security-closed] and
[unchecked][security-open]).  We have not yet implemented mitigations
against either the
[Lucky13](http://www.isg.rhul.ac.uk/tls/Lucky13.html) timing attack or
traffic analysis (e.g. [length-hiding
padding](http://tools.ietf.org/html/draft-pironti-tls-length-hiding-02)).

You can read more about
[attacks](https://github.com/mirleft/ocaml-tls/blob/master/attacks.md)
and our mitigations. We also [documented the
design](https://github.com/mirleft/ocaml-tls/blob/master/design.md) of
`ocaml-tls`.


### Trusted code base

Designed to run on Mirage, the trusted code base of `ocaml-tls` is
small. It includes the libraries already mentioned, `ocaml-tls`,
[`ocaml-asn1-combinators`][ocaml-asn1-combinators],
[`ocaml-x509`][ocaml-x509], and [`ocaml-nocrypto`][ocaml-nocrypto]
(which uses C implementations of block ciphers and hash
algorithms). For arbitrary precision integers needed in asymmetric
cryptography, we rely on
[`zarith`](https://forge.ocamlcore.org/projects/zarith), which wraps
[`libgmp`](https://gmplib.org/). As underlying byte array structure we
use [`cstruct`](https://github.com/mirage/ocaml-cstruct) (which uses
OCaml `Bigarray` as storage).

We should also mention the OCaml runtime, the OCaml compiler, the
operating system on which the source is compiled and the binary is
executed, as well as the underlying hardware. Two effectful frontends
for the pure TLS core are implemented, dealing with side-effects such
as reading and writing from the network:
[Lwt_unix](http://ocsigen.org/lwt/api/Lwt_unix) and
[Mirage](http://www.openmirage.org), so applications can run directly
as a Xen unikernel.

### Why a new TLS implementation?

There are only a few TLS implementations publicly available and most
programming languages bind to OpenSSL, an open source implementation written
in C. There are valid reasons to interface with an existing TLS library,
rather than developing one from scratch, including protocol complexity and
compatibility with different TLS versions and implementations. But from our
perspective the disadvantage of most existing libraries is that they
are written in C, leading to:

  * Memory safety issues, as recently observed by [Heartbleed][] and GnuTLS
    session identifier memory corruption ([CVE-2014-3466][]) bugs;
  * Control flow complexity (Apple's goto fail, [CVE-2014-1266][]);
  * And difficulty in encoding state machines (OpenSSL change cipher suite
    attack, [CVE-2014-0224][]).

Our main reasons for `ocaml-tls` are that OCaml is a modern functional
language, which allows concise and declarative descriptions of the
complex protocol logic and provides type safety and memory safety to help
guard against programming errors. Its functional nature is extensively
employed in our code: the core of the protocol is written in purely
functional style, without any side effects.

[ocaml-nocrypto]: https://github.com/mirleft/ocaml-nocrypto
[ocaml-asn1-combinators]: https://github.com/mirleft/ocaml-asn1-combinators
[ocaml-x509]: https://github.com/mirleft/ocaml-x509

[issues]: https://github.com/mirleft/ocaml-tls/issues
[security-open]: https://github.com/mirleft/ocaml-tls/issues?labels=security+concern&page=1&state=open
[security-closed]: https://github.com/mirleft/ocaml-tls/issues?labels=security+concern&page=1&state=closed

[attacks]: http://eprint.iacr.org/2013/049
[mitls]: http://www.mitls.org
[Fortuna]: https://www.schneier.com/fortuna.html
[HOL]: http://www.infsec.ethz.ch/people/andreloc/publications/lochbihler14iw.pdf
[cheap]: http://people.cs.missouri.edu/~harrisonwl/drafts/CheapThreads.pdf

[Heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
[mostdangerous]: https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
[frankencert]: https://www.cs.utexas.edu/~shmat/shmat_oak14.pdf
[CVE-2014-1266]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1266
[CVE-2014-3466]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3466
[CVE-2014-0224]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224


****

Posts in the TLS series:

 - [Introducing transport layer security (TLS) in pure OCaml][tls-intro]
 - [OCaml-TLS: building the nocrypto library core][nocrypto-intro]
 - [OCaml-TLS: adventures in X.509 certificate parsing and validation][x509-intro]
 - [OCaml-TLS: ASN.1 and notation embedding][asn1-intro]
 - [OCaml-TLS: the protocol implementation and mitigations to known attacks][tls-api]

[tls-intro]: http://openmirage.org/blog/introducing-ocaml-tls
[nocrypto-intro]: http://openmirage.org/blog/introducing-nocrypto
[x509-intro]: http://openmirage.org/blog/introducing-x509
[asn1-intro]: http://openmirage.org/blog/introducing-asn1
[tls-api]: http://openmirage.org/blog/ocaml-tls-api-internals-attacks-mitigation

### Implemented standards

- RFC 2246 - TLS Protocol version 1.0
- RFC 2818 - HTTP over TLS (notably wildcard domain names in X509 certificates)
- RFC 3268 - AES Ciphersuites for TLS
- RFC 4346 - TLS Protocol version 1.1
- RFC 4366 - TLS Extensions (notably Server Name Indication - SNI)
- RFC 5246 - TLS Protocol version 1.2
- RFC 5746 - TLS Renegotiation Indication Extension
- draft-agl-tls-padding-03 - A TLS padding extension
- draft-mathewson-no-gmtunixtime - No UNIX time in client and server hello

### Acknowledgements

Since this is the final post in our series, we would like to thank all
people who reported issues so far: [Anil Madhavapeddy][anil], [Török
Edwin][edwin], [Daniel Bünzli][daniel], [Andreas Bogk][andreas], [Gregor Kopf][greg], [Graham
Steel][graham], [Jerome Vouillon][vouillon], [Amir Chaudhry][amir],
[Ashish Agarwal][ashish]. Additionally, we want to thank the
[miTLS][mitls] team (especially Cedric and Karthikeyan) for fruitful
discussions, as well as the [OCaml Labs][ocamllabs] and
[Mirage][mirage] teams. And thanks to [Peter Sewell][peter] and
[Richard Mortier][mort] for funding within the [REMS][rems], [UCN][ucn], and [Horizon][horizon]
projects. The software was started in [Aftas beach house][aftas] in
Mirleft, Morocco.

[horizon]: http://www.horizon.ac.uk
[mirage]: http://www.openmirage.org
[ocamllabs]: http://www.cl.cam.ac.uk/projects/ocamllabs/
[aftas]: http://www.aftasmirleft.com/
[ucn]: http://usercentricnetworking.eu/
[rems]: http://rems.io
[mort]: http://www.cs.nott.ac.uk/~rmm/
[peter]: http://www.cl.cam.ac.uk/~pes20/
[ashish]: http://ashishagarwal.org
[amir]: http://amirchaudhry.com/
[daniel]: http://erratique.ch/
[vouillon]: https://github.com/vouillon
[graham]: https://twitter.com/graham_steel
[greg]: http://gregorkopf.de/blog/
[andreas]: http://blog.andreas.org/
[edwin]: https://github.com/edwintorok
[anil]: http://anil.recoil.org/
