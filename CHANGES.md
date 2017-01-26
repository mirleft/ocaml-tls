## 0.8.0 (2017-01-??)

* lwt: in Unix.client_of_fd the named argument host is now optional (#336)
* mirage: in client_of_flow the (positional) hostname argument is now optional (#336)
* mirage: adapt to PCLOCK interface (@mattgray #329 #331)
* build system migrated from oasis to topkg (#342)
* mirage: adapt to MirageOS3 (@yomimono @samoht #338 #349 #350 #351 #353)
* lwt: do not crash on double close (@vbmithr #345)
* fixed docstring typos (@mor1 #340)

## 0.7.1 (2016-03-21)

* remove camlp4 dependency (use cstruct ppx and sexplib ppx instead)
* sort client extensions, there are servers which dislike an extension without
  data at the end, thus try to send extensions with data at the end (#319)
* initial GCM support (#310)
* fix `hs_can_handle_appdata` (#315):
    Initially we allowed application data always after the first handshake.

    Turns out, between CCS and Finished there is new crypto_context in place
    which has not yet been authenticated -- bad idea to accept application data
    at that point (beginning of 2015 in OCaml TLS).

    The fix was to only allow application data in Established state (and block
    in Tls_lwt/Tls_mirage when the user requested renegotiation) (December 2015
    in OCaml-TLS).

    Renegotiation was also turned off by default when we introduced resumption
    (mid October 2015): both features together (without mitigating via session
    hash) allow the triple handshake.

    It turns out, the server side can happily accept application data from the
    other side when it just sent a HelloRequest (and waits for the ClientHello;
    same is true for the client side, waiting for the ServerHello in
    renegotiation case might be interleaved with application data) to let the
    client initiate a new handshake.  By this commit, OCaml-TLS allows
    application data then.

    In the end, it is a pretty academic thing anyways, since nobody uses
    renegotiation with OCaml-TLS in the field.
* during verification of a digitally signed: checked that the used hash
  algorithm is one of the configured ones (#313)
* unify return type of handshake and change cipher spec handler (#314)
* separate client and server extensions (#317)
* type equality (no longer generative error type), use result (#318)
* removed Printer (was barely useful)

## 0.7.0 (2015-12-04)

* session resumption (via session ID) support (#283)
  Config contains `session_cache : SessionID.t -> epoch_data option`
  and `cached_session : epoch_data option`
* session hash and extended master secret (RFC 7627) support (#287)

### semantic changes
* disable renegotiation by default (#300)
* blocking semantics (both Mirage and Lwt) while renegotiating (#304)
* `Engine.handshake_in_progress` no longer exist
* `Hex_fingerprint / `Fingerprint authenticators no longer exist
* Mirage X509 does no longer prefix keys and trust anchors with "tls/" in the path

### minor fixes
* fix concurrent read/write in tls_mirage (#303)
* expose own_random and peer_random in epoch_data (@cfcs, #297)
* public key pinning (X509_lwt) via `Hex_key_fingerprint / `Key_fingerprint (#301)
* certificate chain and peer certificate are exposed via epoch_data (new path-building X.509 interface)

## 0.6.0 (2015-07-02)

* API: dropped 'perfect' from forward secrecy in Config.Ciphers:
  fs instead of pfs, fs_of instead of pfs_of
* API: type epoch_data moved from Engine to Core
* removed Cstruct_s now that cstruct (since 1.6.0) provides
  s-expression marshalling
* require at least 1024 bit DH group, use FFDHE 2048 bit DH group
  by default instead of oakley2 (logjam)
* more specific alerts:
  - UNRECOGNIZED_NAME: if hostname in SNI does not match
  - UNSUPPORTED_EXTENSION: if server hello has an extension not present in
    client hello
  - ILLEGAL_PARAMETER: if a parse error occured
* encrypt outgoing alerts
* fix off-by-one in handling empty TLS records: if a record is less than 5
  bytes, treat as a fragment. exactly 5 bytes might already be a valid
  application data frame

## 0.5.0 (2015-05-02)

* updates to extension enum (contributed by Dave Garrett #264)
* removed entropy feeding (done by nocrypto) #265
* Tls_lwt file descriptor lifecycle: not eagerly close file descriptors #266

## 0.4.0 (2015-03-19)

* client authentication (both client and server side)
* server side SNI configuration (see sni.md)
* SCSV server-side downgrade prevention (by Gabriel de Perthuis @g2p #5)
* remove RC4 ciphers from default config #8
* support for AEAD ciphers, currently CCM #191
* proper bounds checking of handshake fragments #255
* disable application data between CCS and Finished #237
* remove secure renegotiation configuration option #256
* expose epoch in mirage interface, implement 2.3.0 API (error_message)
* error reporting (type failure in engine.mli) #246
* hook into Lwt event loop to feed RNG #254

## 0.3.0 (2014-12-21)

* X509_lwt provides `Fingerprints and `Hex_fingerprints constructor for
  checking fingerprints of certificates instead of trusting trust
  anchors #206 #207
* client configuration requires an authenticator #202
* server certificate must be at least Config.min_rsa_key_size bits
* expose epoch via lwt interface #208
* mirage-2.2.0 compatibility #212
* cleanups of mirage interface #213
* nocrypto-0.3.0 compatibility #194 #209 #210

## 0.2.0 (2014-10-30)

* distinguish between supported hash and mac algorithms (using Nocrypto.Hash)
  and those which may occur on the wire #189
* expose trust anchor when authenticating certificate (requires x509 >=0.2) #178
* information about the active session is exposed via epoch : state -> epoch
* distinguish between supported ciphersuites (type ciphersuite) and
  known ciphersuites (type any_ciphersuite) #173
* distinguish between supported versions by the stack (type tls_version)
  and readable versions (tls_any_version), which might occur in a tls
  record or client_hello read from the network #179 #172
* support > TLS-1.2 client hellos (as reported by ssllabs.com #161)
* support iOS 6 devices (who propose NULL ciphers - reported in #160)
* send minimal protocol version in record layer of client hello
  (maximum version is in the client hello itself) (RFC5246, E.1) #165

## 0.1.0 (2014-07-08)

* initial beta release