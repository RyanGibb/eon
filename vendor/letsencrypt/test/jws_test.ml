open OUnit2

open Letsencrypt__Acme_common

let testkey_pem = "
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjGBnd5E+TChG/
Lup5FRuYwN7RX7Ef15Yt27SKF54uWuYPaapZd8/0h5IoCluffiDxO4BL2DnOGrwQ
tDeSaOv4pXzoYAyAjpUBwaWrdCvOlMJ//fQBvv7NrCt9FoU41rUfATM9jUoecZWT
ElzzmA2TBgj1JjZEde2+WffOznAhM2t2iyoRd5oiRVgESFuE27nimneTGjpO5YuL
17qld5Z60TCaUHC1ZmU+iJvaPdPEsGSwpl+jIXJ6TfzSYeAkC6ZD8jZ+OP3z/3ua
TeKE5jgCBV0IOPXP8YKhmQblGrudsIbKizIpbINfTRmz6c2pWGgt4i9cLiedZ0kx
nquiDHJBAgMBAAECggEABaFh98xKtEe0QbAXOGYPc3m5tIl5teNFmhC30NIt1fKj
QFfTdUkpDuQjGarLE4DgLnb2EvtTEJL9XXEobRD8o8Mvnf/Oo4vVcjATzFTSprot
udhpKbdrcBxADkeGCU8aecCw/WpQv4E7rwQuKYx4LrBgPbrDLu6ZFMZ8hEQ+R7Zn
j0jWswOZEwM5xNHZ8RlwP4xsyFChvBR43lymHwDwQegd7ukbY0OcwXZ+2sxcKltr
LBZKKFPzMugKnMbZtwm3TRIUTDGjB+IZGU7dPXgF8cK4KR4yDRZ5HKIZWbqxCPCP
6TphI+Jz83OxpXU9R8rfPgUhnBgqwTdDpc5pGfmyiQKBgQD+I1TKDW5tF0fXWnza
Xwoe0ULUM8TRXWBJmxfb1OkzmNLiq/jor6zxibXOas5EzzH5zKd8/HVVBlDfgRh4
IwhfbXavIn7MMBOXg0TQjia4y9KIf2/HpdzsWaE2dpjM+wEvlOb2ea1C4/T1gSfy
miI4kWIOz/iiWcPmiADk7hMcaQKBgQDkwgupZgFS6psRYtG0yu5S2kBJyWsGo02w
kSwwZt6oEmagzF0d5JlyRss6uqbsaUzI1Ek17/m5ZEZLNoxi4abCw+kRHOoS9gWd
KumNbli1dn4m3EVc1V+b1nWAsuC8ak5QIhRFumgNyQN7W+BS6TfLn4ONmKGz6uog
njlfNdPMGQKBgFa5/ex6Cu4lnLmsQqFO/6gmp5S9GfSM1hgoWksF7JNUGtuJ7oaR
tQY0hZusrTmkL5zcr2eiy/O5FQ5BAvW0lt3iADeiIP1ThswU2v4FFMfJns5AFwhd
3Pe3WqG4dUq2eeAgA3Wnbm4+VtEVQ2myGe2OB5WgeWwGEClyzkNRz6nJAoGAPN4c
+D/6DjP6es/OeMqeS1FjVb7QSX3eSCL4nRBiIlpzEEoQZMnUwoFvxfqwO6txEObb
bAykZ930jkK/a/gaxSwXscP9zHnF2KH4bvdzhyU2P+TQV/k2bWLM9SejgL7Qg6Xt
uvf0g+Z+lK5HrAf+HqIdAOoh7JuPHIq9PUY3StECgYEAoYP7hkj8TUygnkJcHxwM
MwdqBsTdyr8O2ZjMTa/UMWlBi7kjg8KblzsRB4g/p1m2/wgyC0Yhv3VBf2le8/Rr
OfNArBggDydmCgQ0I9+IxM+IQNP17/SU5s71daxeltJOxE+PSy/WsH5TMEnQ+CMr
irbM4XSw2jtvX7qeUzcFY/E=
-----END PRIVATE KEY-----
"

let expected_protected =
  "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6" ^
  "IlJTQSIsIm4iOiI0eGdaM2VSUGt3b1J2eTdxZVJVYm1NRGUwVi14" ^
  "SDllV0xkdTBpaGVlTGxybUQybXFXWGZQOUllU0tBcGJuMzRnOFR1" ^
  "QVM5ZzV6aHE4RUxRM2ttanItS1Y4NkdBTWdJNlZBY0dscTNRcnpw" ^
  "VENmXzMwQWI3LXphd3JmUmFGT05hMUh3RXpQWTFLSG5HVmt4SmM4" ^
  "NWdOa3dZSTlTWTJSSFh0dmxuM3pzNXdJVE5yZG9zcUVYZWFJa1ZZ" ^
  "QkVoYmhOdTU0cHAza3hvNlR1V0xpOWU2cFhlV2V0RXdtbEJ3dFda" ^
  "bFBvaWIyajNUeExCa3NLWmZveUZ5ZWszODBtSGdKQXVtUV9JMmZq" ^
  "ajk4Xzk3bWszaWhPWTRBZ1ZkQ0RqMXpfR0NvWmtHNVJxN25iQ0d5" ^
  "b3N5S1d5RFgwMFpzLW5OcVZob0xlSXZYQzRubldkSk1aNnJvZ3h5" ^
  "UVEifSwibm9uY2UiOiJub25jZSJ9"

let expected_payload = "eyJNc2ciOiJIZWxsbyBKV1MifQ"

let expected_signature =
  "eAGUikStX_UxyiFhxSLMyuyBcIB80GeBkFROCpap2sW3EmkU_ggF" ^
  "knaQzxrTfItICSAXsCLIquZ5BbrSWA_4vdEYrwWtdUj7NqFKjHRa" ^
  "zpLHcoR7r1rEHvkoP1xj49lS5fc3Wjjq8JUhffkhGbWZ8ZVkgPdC" ^
  "4tMBWiQDoth-x8jELP_3LYOB_ScUXi2mETBawLgOT2K8rA0Vbbmx" ^
  "hWNlOWuUf-8hL5YX4IOEwsS8JK_TrTq5Zc9My0zHJmaieqDV0UlP" ^
  "k0onFjPFkGm7MrPSgd0MqRG-4vSAg2O4hDo7rKv4n8POjjXlNQvM" ^
  "9IPLr8qZ7usYBKhEGwX3yq_eicAwBw"

let rsa_key () =
  match X509.Private_key.decode_pem (Cstruct.of_string testkey_pem) with
  | Ok `RSA skey -> `RSA skey
  | Ok _ -> assert_failure "unsupported key type"
  | Error `Msg e -> assert_failure e

let string_member key json =
  match Yojson.Basic.Util.member key json with
  | `String s -> Ok s
  | _ -> Error (`Msg (Fmt.str "couldn't find string %s in %a"
                        key Yojson.Basic.pp json))

let json_of_string s =
  try Ok (Yojson.Basic.from_string s) with
    Yojson.Json_error str -> Error (`Msg str)

let jws_encode_somedata () =
  let priv_key = rsa_key () in
  let data  = {|{"Msg":"Hello JWS"}|} in
  let nonce = "nonce" in
  let protected = [ "jwk", Jwk.encode (X509.Private_key.public priv_key) ] in
  let jws = Jws.encode ~protected ~data ~nonce priv_key in
  match json_of_string jws with
  | Ok json -> json
  | Error (`Msg e) -> assert_failure e

let test_member member expected _ctx =
  let jws = jws_encode_somedata () in
  match string_member member jws with
  | Ok protected -> assert_equal protected expected
  | Error (`Msg e) -> assert_failure e

let test_encode_protected = test_member "protected" expected_protected
let test_encode_payload = test_member "payload" expected_payload
let test_encode_signature = test_member "signature" expected_signature

let test_decode_null _ctx =
  assert_equal (Jws.decode "{}") (Error (`Msg "couldn't find string protected in {}"))

let jws_decode_somedata () =
  let data = Printf.sprintf
      {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
      expected_protected expected_payload expected_signature in
  Jws.decode data

let test_decode_rsakey _ctx =
  let jws = jws_decode_somedata () in
  let key = rsa_key () in
  match jws with
  | Error (`Msg e) -> assert_failure e
  | Ok (protected, _payload) ->
    let pub = X509.Private_key.public key in
    assert_equal protected.Jws.jwk (Some pub)

(* XXX. at this stage we probably wont the expected payload to be on some
 * global variable. *)
let test_decode_payload _ctx =
  match jws_decode_somedata () with
  | Error (`Msg e) -> assert_failure e
  | Ok (_, payload) ->
    assert_equal payload {|{"Msg":"Hello JWS"}|}

let rfc7520_payload =
  "It\xe2\x80\x99s a dangerous business, Frodo, going out your " ^
  "door. You step onto the road, and if you don't keep your feet, " ^
  "there\xe2\x80\x99s no knowing where you might be swept off " ^
  "to."

let rfc7520_4_1_rsa_pkcs_sign _ctx =
  let key =
    (* Section 3.4, Figure 4 *)
    let decode_z str =
      match Letsencrypt__B64u.urldecodez str with Ok x -> x | Error _ -> assert false
    in
    let e = decode_z "AQAB"
    and p = decode_z
        ("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" ^
         "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" ^
         "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" ^
         "bUq0k")
    and q = decode_z
        ("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" ^
         "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" ^
         "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" ^
         "s7pFc")
    in
    match Mirage_crypto_pk.Rsa.priv_of_primes ~e ~p ~q with
    | Ok p -> `RSA p
    | Error _ -> assert false
  in
  let b64_payload =
    "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" ^
    "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" ^
    "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" ^
    "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
  in
  assert_equal b64_payload (Letsencrypt__B64u.urlencode rfc7520_payload);
  let protected = [ "kid", `String "bilbo.baggins@hobbiton.example" ] in
  let rfc_out =
    let signature =
      "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK" ^
      "ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J" ^
      "IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w" ^
      "W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP" ^
      "xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f" ^
      "cIe8u9ipH84ogoree7vjbU5y18kDquDg"
    and prot_header =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX" ^
      "hhbXBsZSJ9"
    in
    json_to_string ~comma:", " ~colon:": " (`Assoc [
        ("protected", `String prot_header) ;
        ("payload", `String b64_payload) ;
        ("signature", `String signature) ;
      ])
  in
  let signature = Jws.encode ~protected ~data:rfc7520_payload key in
  assert_equal rfc_out signature

let rfc7520_4_3_es512_sign _ctx =
  let key =
    let d =
      match Letsencrypt__B64u.urldecode
        ("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" ^
         "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")
      with
      | Ok d -> Cstruct.of_string d
      | Error _ -> assert false
    in
    match Mirage_crypto_ec.P521.Dsa.priv_of_cstruct d with
    | Ok k -> k
    | Error _ -> assert false
  in
  let pub = Mirage_crypto_ec.P521.Dsa.pub_of_priv key in
  let cs = Mirage_crypto_ec.P521.Dsa.pub_to_cstruct pub in
  let x, y = Cstruct.split cs ~start:1 66 in
  let rfc_x = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"
  and rfc_y = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
  in
  assert_equal rfc_x (Letsencrypt__B64u.urlencode (Cstruct.to_string x));
  assert_equal rfc_y (Letsencrypt__B64u.urlencode (Cstruct.to_string y));
  let rfc_signature =
    "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNl" ^
    "aAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mt" ^
    "PBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBp" ^
    "HABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
  in
  let data =
    let prot_header =
      `Assoc [ "alg", `String "ES512" ; "kid", `String "bilbo.baggins@hobbiton.example" ]
      |> json_to_string |> Letsencrypt__B64u.urlencode
    in
    assert_equal prot_header "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9";
    json_to_string ~comma:", " ~colon:": " (`Assoc [
        ("protected", `String prot_header) ;
        ("payload", `String (Letsencrypt__B64u.urlencode rfc7520_payload)) ;
        ("signature", `String rfc_signature) ;
      ])
  in
  match Jws.decode ~pub:(`P521 pub) data with
  | Ok _ -> ()
  | Error _ -> assert false


let all_tests = [
  "test_encode_protected" >:: test_encode_protected;
  "test_encode_payload" >:: test_encode_payload;
  "test_encode_signature" >:: test_encode_signature;

  "test_decode_null" >:: test_decode_null;
  "test_decode_rsakey" >:: test_decode_rsakey;
  "test_decode_payload" >:: test_decode_payload;

  "rfc_7520_4_1_rsa_pkcs_sign" >:: rfc7520_4_1_rsa_pkcs_sign;
  "rfc_7520_4_3_es512_sign" >:: rfc7520_4_3_es512_sign;
]
