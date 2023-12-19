
val pub_of_z : e:Z.t -> n:Z.t -> (Mirage_crypto_pk.Rsa.pub, [> `Msg of string ]) result
val pub_to_z : Mirage_crypto_pk.Rsa.pub -> Z.t * Z.t

val sign : Mirage_crypto.Hash.hash -> X509.Private_key.t -> string -> string
val verify : Mirage_crypto.Hash.hash -> X509.Public_key.t -> string -> string -> bool

val sha256 : string -> string
