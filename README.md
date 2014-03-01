ocaml-tls
==========

TLS 1.0 support in pure (O)Caml.

status
======

Client and server are working (mirage-server and mirage-client applications).

The mirage-server uses a tap0 interface 10.0.0.2 and listens on port 80.

The mirage-client uses a mirage socket_stackv4 (`Socket instead of `Direct due to issues in mirage) and connects to 127.0.0.1 port 4433 (where openssl s_client listens by default).

The combined mirage-server-client connects to 10.0.0.1 port 4433 when a connection is made to it (10.0.0.2 port 80).

- RFC 2246 - TLS Protocol version 1.0
- RFC 4366 - TLS extensions
- RFC 5746 - TKS Renegotiation Indication Extension

work in progress

- RFC 6520 - TLS Heartbeat extension
- RFC 3268 - AES Ciphersuites for TLS
- RFC 4492 - Elliptic Curve Cryptography Ciphersuites for TLS

ciphersuites
============

currently we use the primitives from cryptokit (but are in the process of switching to ocaml-nocrypto).

key exchange
- RSA
- DHE_RSA (currently only server side)

encryption
- RC4_128
- 3DES-CBC

mac
- MD5
- SHA1

TODO (before any deployment)
============================

- fix random (currently 0 or a constant)
- certificate verification (not even signature is checked)
- fix error reporting
- bits and pieces from useful extensions (heartbeat)
- remove snakeoil key and cert from repository
