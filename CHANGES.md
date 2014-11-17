master:
* require an authenticator to be present for a client

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