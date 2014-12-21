0.3.0 (2014-12-21):
* X509_lwt provides `Fingerprints and `Hex_fingerprints constructor for checking fingerprints of certificates instead of trusting trust anchors
* client configuration requires an authenticator
* server certificate must be at least Config.min_rsa_key_size bits
* expose epoch via lwt interface
* mirage-2.2.0 compatibility
* cleanups of mirage interface
* nocrypto-0.3.0 compatibility

0.2.0 (2014-10-30):
* expose trust anchor when authenticating the certificate (requires x509 >= 0.2)
* information about the active session is exposed via epoch : state -> epoch
* distinguish between supported ciphersuites (type ciphersuite) and
  known ciphersuites (type any_ciphersuite)
* distinguish between supported versions by the stack (type tls_version)
  and readable versions (tls_any_version), which might occur in a tls
  record or client_hello read from the network
* support > TLS-1.2 client hellos (as reported by ssllabs.com)
* support iOS 6 devices (who propose NULL ciphers - reported in #160)
* send minimal protocol version in record layer of client hello
  (maximum version is in the client hello itself) (RFC5246, E.1)

0.1.0 (2014-07-08):
* initial beta release