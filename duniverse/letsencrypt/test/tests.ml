open OUnit2

let () =
  let tests =
    B64u_test.all_tests @ Jwk_test.all_tests @ Jws_test.all_tests
  in
  let suite = "suite">::: tests in
  Mirage_crypto_rng_unix.initialize ();
  run_test_tt_main suite
