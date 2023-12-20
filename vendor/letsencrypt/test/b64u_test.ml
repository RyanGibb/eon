open OUnit2

let test_decodez_216p1 _ctx =
  let e64 = "AQAB" in
  match Letsencrypt__B64u.urldecodez e64 with
  | Error (`Msg e) -> assert_failure e
  | Ok e ->
    let got = Z.format "%x" e in
    let expected = "10001" in
    assert_equal got expected

let test_encodez_216p1 _ctx =
  let e = Z.of_int 65537 in
  let e64 = Letsencrypt__B64u.urlencodez e in
  assert_equal e64 "AQAB"

(* Appendix A.1.1 of RFC7515. *)
let test_encode _ctx =
  let msg =
    "\123\034\116\121\112\034\058\034\074\087\084\034\044\013\010\032\034" ^
    "\097\108\103\034\058\034\072\083\050\053\054\034\125"
  in
  let msg64 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" in
  assert_equal (Letsencrypt__B64u.urlencode msg) msg64

let all_tests = [
  "test_encodez_216p1" >:: test_encodez_216p1;
  "tests_decodez_216p1" >:: test_decodez_216p1;
  "test_encode" >:: test_encode;
]
