ocaml-tls
==========

TLS 1.0 support in pure (O)Caml.

status
======

client and server state machine are working (using mirage-server and mirage-client (currently rather mirage-server-client (due to mirage issue in mirage-client), which connects to 10.0.0.1 on port 4433 when a connection is made to 10.0.0.2 on port 80 [where mirage-server listens to]).

ciphersuites
============

currently we use the primitives from cryptokit (but are in the process of switching to ocaml-nocrypto).

- key exchange: RSA and DHE_RSA are supported (client side currently only RSA)
- encryption: RC4_128 (stream cipher), 3DES-CBC
- hash: MD5, SHA1

TODO (before any deployment)
============================

- fix random (currently 0 or a constant)
- certificate verification (not even signature is checked)
- fix error reporting
- bits and pieces from useful extensions (secure renegotiation, heartbeat)
- remove snakeoil key and cert from repository
