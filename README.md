ocaml-tls
==========

TLS 1.0 support in pure (O)Caml.

status
======

Client and server are working (mirage-server and mirage-client applications).

The mirage-server uses a mirage socket_stackv4 and listens on port 4433. Run the server ``./mir-mirage-tls-server``, and use ``openssl s_client -tls1 -msg -connect 127.0.0.1:4433`` to start a secure conversation.

The mirage-client uses a mirage socket_stackv4 and connects to 127.0.0.1 port 4433. Run ``openssl s_server -tls1 -key server.key -cert server.pem -msg`` before running ``./mir-mirage-tls-client``.

You can pass ``openssl s_server`` a ``-cipher`` parameter (following should work: ``EDH-RSA-DES-CBC3-SHA DES-CBC3-SHA RC4-SHA RC4-MD5``.

implemented

- RFC 2246 - TLS Protocol version 1.0
- RFC 4366 - TLS extensions
- RFC 5746 - TLS Renegotiation Indication Extension

work in progress

- RFC 6520 - TLS Heartbeat extension
- RFC 3268 - AES Ciphersuites for TLS
- RFC 4492 - Elliptic Curve Cryptography Ciphersuites for TLS

ciphersuites
============

currently we use the primitives from cryptokit (but are in the process of switching to ocaml-nocrypto).

key exchange
- DHE_RSA
- RSA

encryption
- 3DES-CBC
- RC4_128

mac
- SHA1
- MD5

TODO (before any deployment)
============================

- fix random (currently 0 -- Flow.default_config.rng)
- fix config (currently Flow.default_config and Server.default_server_config)
- certificate verification (not even signature is checked)
- fix error reporting
- bits and pieces from useful extensions (heartbeat)
- remove snakeoil key and cert from repository
