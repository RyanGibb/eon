let pub_of_z ~e ~n = Mirage_crypto_pk.Rsa.pub ~e ~n
let pub_to_z (key : Mirage_crypto_pk.Rsa.pub) =
  Mirage_crypto_pk.Rsa.(key.e, key.n)

let sign hash priv data =
  let data = Mirage_crypto.Hash.digest hash (Cstruct.of_string data) in
  let ecdsa (r, s) = Cstruct.(to_string (append r s)) in
  match priv with
  | `RSA key -> Cstruct.to_string (Mirage_crypto_pk.Rsa.PKCS1.sign ~key ~hash (`Digest data))
  | `P256 key -> ecdsa (Mirage_crypto_ec.P256.Dsa.sign ~key data)
  | `P384 key -> ecdsa (Mirage_crypto_ec.P384.Dsa.sign ~key data)
  | `P521 key -> ecdsa (Mirage_crypto_ec.P521.Dsa.sign ~key data)
  | _ -> assert false

let verify hash pub data signature =
  let data = Mirage_crypto.Hash.digest hash (Cstruct.of_string data)
  and signature = Cstruct.of_string signature
  in
  match pub with
  | `RSA key ->
    let hashp h = h = hash in
    Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature (`Digest data)
  | `P256 key when Cstruct.length signature = 64 ->
    let s = Cstruct.split signature 32 in
    Mirage_crypto_ec.P256.Dsa.verify ~key s data
  | `P384 key when Cstruct.length signature = 96 ->
    let s = Cstruct.split signature 48 in
    Mirage_crypto_ec.P384.Dsa.verify ~key s data
  | `P521 key when Cstruct.length signature = 132 ->
    let s = Cstruct.split signature 66 in
    Mirage_crypto_ec.P521.Dsa.verify ~key s data
  | _ -> false

let sha256 x =
  Cstruct.of_string x |> Mirage_crypto.Hash.SHA256.digest |> Cstruct.to_string
