open OUnit2

let suite =
  "All" >::: [
    "Reader" >::: Readertests.reader_tests ;
    "Writer" >::: Writertests.writer_tests ;
    "ReaderWriter" >::: Readerwritertests.readerwriter_tests ;

    "Handshake" >::: Handshakes.handshake_tests ;

    "X509" >::: X509tests.x509_tests ;
  ]
