open OUnit2

let suite =
  "All" >::: [
    "Reader" >::: Readertests.reader_tests ;
    "Writer" >::: Writertests.writer_tests ;
  ]
