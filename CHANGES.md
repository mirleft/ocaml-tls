(trunk):
* client authentication (both client and server side)
* server side SNI configuration possible (see sni.md)
* SCSV server-side downgrade prevention (contributed by Gabriel de Perthuis @g2p #5)
* remove RC4 ciphers from default config #8
* support for AEAD ciphers, currently CCM #191

0.3.0 (2014-12-21):
* X509_lwt provides `Fingerprints and `Hex_fingerprints constructor for
  checking fingerprints of certificates instead of trusting trust
  anchors #206 #207
* client configuration requires an authenticator #202
* server certificate must be at least Config.min_rsa_key_size bits
* expose epoch via lwt interface #208
* mirage-2.2.0 compatibility #212
* cleanups of mirage interface #213
* nocrypto-0.3.0 compatibility #194 #209 #210

0.2.0 (2014-10-30):
* distinguish between supported hash and mac algorithms (using Nocrypto.Hash)
  and those which may occur on the wire #189
* expose trust anchor when authenticating the certificate (requires x509 >= 0.2) #178
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

0.1.0 (2014-07-08):
* initial beta release