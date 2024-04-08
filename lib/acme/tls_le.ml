(* adapted from
   https://github.com/avsm/eeww/blob/ea7c8e5513e6524b28b24947de6bf0fabef78ef9/src/tls_le/tls_le.ml *)

exception Le_error of string

let errcheck = function Ok v -> v | Error (`Msg m) -> raise (Le_error m)
let gen_account_key () = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:2048 ())
let gen_private_key () = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:4096 ())

let gen_csr ~private_key ~email ~org ~domain =
  (* looks like we might need to use Subject Alternative Name (SAN), rfc2818
      e.g. chrome doesn't look at CN anymore
      https://developer.chrome.com/blog/chrome-58-deprecations/#remove_support_for_commonname_matching_in_certificates
      relevant rfc6125/rfc9525
      also, do we need the org? *)
  let dn =
    X509.Distinguished_name.
      [
        Relative_distinguished_name.(
          singleton (CN (Domain_name.to_string domain)));
        Relative_distinguished_name.(singleton (Mail email));
        Relative_distinguished_name.(singleton (O org));
      ]
  in
  X509.Signing_request.create dn private_key |> errcheck

let gen_cert ?account_key ?private_key ~email ~org ~domain ~endpoint ~solver env
    =
  let account_key =
    Option.value account_key ~default:(Lazy.force (lazy (gen_account_key ())))
  in
  let private_key =
    Option.value private_key ~default:(Lazy.force (lazy (gen_private_key ())))
  in
  let csr = gen_csr ~private_key ~email ~org ~domain in
  let sleep n = Eio.Time.sleep env#clock (float_of_int n) in
  let le =
    Letsencrypt.Client.initialise env ~endpoint ~email account_key |> errcheck
  in
  let cert =
    Letsencrypt.Client.sign_certificate env solver le sleep csr |> errcheck
  in
  (cert, account_key, private_key, csr)

let tls_config ?alpn_protocols ~cert ~private_key () =
  let certificates : Tls.Config.own_cert = `Single (cert, private_key) in
  Tls.Config.(
    server ?alpn_protocols ~version:(`TLS_1_0, `TLS_1_3) ~certificates
      ~ciphers:Ciphers.supported ())
