(* adapted from
   https://github.com/avsm/eeww/blob/ea7c8e5513e6524b28b24947de6bf0fabef78ef9/src/tls_le/tls_le.ml *)

exception Le_error of string

let errcheck = function Ok v -> v | Error (`Msg m) -> raise (Le_error m)
let gen_account_key () = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:2048 ())
let gen_private_key () = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:4096 ())

let gen_csr ~private_key ~email ?(org = None) domains =
  let open X509 in
  match List.map Domain_name.to_string domains with
  | [] -> raise (Invalid_argument "Must specify at least one domain")
  | names ->
      let dn =
        let open X509.Distinguished_name in
        [ Relative_distinguished_name.(singleton (Mail email)) ]
        @
        match org with
        | Some org -> [ Relative_distinguished_name.(singleton (O org)) ]
        | None -> []
      in
      let extensions =
        let extensions =
          Extension.(
            singleton Subject_alt_name
              (false, General_name.(General_name.singleton DNS names)))
        in
        Signing_request.Ext.(add Extensions extensions empty)
      in
      X509.Signing_request.create dn private_key ~extensions |> errcheck

let gen_cert ?account_key ?private_key ~email ?(org = None) domains ~endpoint
    ~solver env =
  let account_key =
    Option.value account_key ~default:(Lazy.force (lazy (gen_account_key ())))
  in
  let private_key =
    Option.value private_key ~default:(Lazy.force (lazy (gen_private_key ())))
  in
  let csr = gen_csr ~private_key ~email ~org domains in
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
