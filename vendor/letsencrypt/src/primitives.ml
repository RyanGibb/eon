let pub_of_z ~e ~n = Mirage_crypto_pk.Rsa.pub ~e ~n
let pub_to_z (key : Mirage_crypto_pk.Rsa.pub) =
  Mirage_crypto_pk.Rsa.(key.e, key.n)

let sign hash priv data =
  let module H = (val (Digestif.module_of_hash' hash)) in
  let data = H.to_raw_string (H.digest_string data) in
  let ecdsa (r, s) = r ^ s in
  match priv with
  | `RSA key -> Mirage_crypto_pk.Rsa.PKCS1.sign ~key ~hash (`Digest data)
  | `P256 key -> ecdsa (Mirage_crypto_ec.P256.Dsa.sign ~key data)
  | `P384 key -> ecdsa (Mirage_crypto_ec.P384.Dsa.sign ~key data)
  | `P521 key -> ecdsa (Mirage_crypto_ec.P521.Dsa.sign ~key data)
  | _ -> assert false

let verify hash pub data signature =
  let module H = (val (Digestif.module_of_hash' hash)) in
  let data = H.to_raw_string (H.digest_string data) in
  match pub with
  | `RSA key ->
    let hashp h = h = hash in
    Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature (`Digest data)
  | `P256 key when String.length signature = 64 ->
    let s = String.sub signature 0 32, String.sub signature 32 32 in
    Mirage_crypto_ec.P256.Dsa.verify ~key s data
  | `P384 key when String.length signature = 96 ->
    let s = String.sub signature 0 48, String.sub signature 48 48 in
    Mirage_crypto_ec.P384.Dsa.verify ~key s data
  | `P521 key when String.length signature = 132 ->
    let s = String.sub signature 0 66, String.sub signature 66 66 in
    Mirage_crypto_ec.P521.Dsa.verify ~key s data
  | _ -> false

let sha256 x =
  Digestif.SHA256.(to_raw_string (digest_string x))
