open Capnp_rpc_lwt

let read_pem filepath decode_pem =
  try
    match Eio.Path.is_file filepath with
    | true ->
        Some
          (Eio.Path.load filepath |> Cstruct.of_string |> decode_pem
         |> Tls_le.errcheck)
    | false -> None
  with exn ->
    let _fd, path = filepath in
    Format.fprintf Format.err_formatter "error reading %s %a\n" path Eio.Exn.pp
      exn;
    Format.pp_print_flush Format.err_formatter ();
    None

let write_pem filepath pem =
  try
    Eio.Path.save ~create:(`Or_truncate 0o600) filepath
      (pem |> Cstruct.to_string)
  with exn ->
    let _fd, path = filepath in
    Format.fprintf Format.err_formatter "error saving %s %a\n" path Eio.Exn.pp
      exn;
    Format.pp_print_flush Format.err_formatter ();
    raise (Sys_error "Failed to write to file")

let acme_pool = Eio.Pool.create 1 (fun () -> ())

let cert ~sw env prod endpoint server_state update state_dir callback email org
    domains =
  let account_dir = Eio.Path.(env#fs / state_dir / "accounts") in
  let load_account_key email =
    read_pem
      Eio.Path.(account_dir / email / "account.pem")
      X509.Private_key.decode_pem
  in
  let save_account_key email key =
    let ( / ) = Eio.Path.( / ) in
    let dir = account_dir / email in
    Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 dir;
    let filepath = dir / "account.pem" in
    write_pem filepath (X509.Private_key.encode_pem key)
  in

  let cert_dir = Eio.Path.(env#fs / state_dir / "certs") in
  let load_private_key domain =
    read_pem
      Eio.Path.(cert_dir / Domain_name.to_string domain / "privkey.pem")
      X509.Private_key.decode_pem
  in
  let save_private_key domain key =
    let ( / ) = Eio.Path.( / ) in
    let dir = cert_dir / Domain_name.to_string domain in
    Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 dir;
    let filepath = dir / "privkey.pem" in
    write_pem filepath (X509.Private_key.encode_pem key)
  in

  let load_cert domain =
    read_pem
      Eio.Path.(cert_dir / Domain_name.to_string domain / "fullcert.pem")
      X509.Certificate.decode_pem_multiple
  in
  let save_cert domain key =
    let ( / ) = Eio.Path.( / ) in
    let dir = cert_dir / Domain_name.to_string domain in
    Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 dir;
    let filepath = dir / "fullcert.pem" in
    write_pem filepath (X509.Certificate.encode_pem_multiple key)
  in

  let provision_cert =
    Dns_acme.provision_cert prod endpoint server_state update env
  in
  match callback with
  | None -> Service.fail "No callback parameter."
  | Some callback -> (
      let callback_result =
        try
          let domains = List.map Domain_name.of_string_exn domains in
          let domain =
            match domains with
            | [] -> raise (Invalid_argument "Must specify at least one domain.")
            | domain :: _ -> domain
          in
          List.iter
            (fun subdomain ->
              if not (Domain_name.is_subdomain ~subdomain ~domain) then
                raise
                  (Invalid_argument
                     (Fmt.str "Invalid subdomain %a of %a" Domain_name.pp
                        subdomain Domain_name.pp domain)))
            domains;
          let rec renew () =
            let provision () =
              Eio.Pool.use acme_pool @@ fun () ->
              let cert, account_key, private_key, _csr =
                provision_cert ?account_key:(load_account_key email)
                  ?private_key:(load_private_key domain) ~email ~org domains
              in
              save_account_key email account_key;
              save_private_key domain private_key;
              save_cert domain cert;
              (cert, private_key, true)
            in
            let now =
              Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
            in
            let get_renew_date cert =
              let _from, until = X509.Certificate.validity (List.hd cert) in
              (* renew 30 days before expiry *)
              Option.get (Ptime.sub_span until (Ptime.Span.v (30, 0L)))
            in
            let cert, private_key, renewed =
              match (load_cert domain, load_private_key domain) with
              (* check if cert out of date*)
              | Some cert, Some private_key -> (
                  match Ptime.is_later now ~than:(get_renew_date cert) with
                  | false ->
                      Eio.traceln "Cert renew date is %a, reading from disk"
                        Ptime.pp (get_renew_date cert);
                      (cert, private_key, false)
                  | true ->
                      Eio.traceln "Cert renew date is %a, provisioning one"
                        Ptime.pp (get_renew_date cert);
                      provision ())
              (* if we don't have them cached, provision them *)
              | _ ->
                  Eio.traceln "No cert found for %a, provisioning one"
                    Domain_name.pp domain;
                  provision ()
            in
            let renew_date = get_renew_date cert in
            Eio.Fiber.fork ~sw (fun () ->
                Eio.traceln "Renewing at %a" Ptime.pp renew_date;
                Eio.Time.sleep_until env#clock (Ptime.to_float_s renew_date);
                ignore @@ renew ());
            Cert_callback.register callback true "" (Some cert)
              (Some private_key) renewed
          in
          renew ()
        with
        | Tls_le.Le_error msg ->
            Cert_callback.register callback false msg None None false
        | e ->
            let msg = Printexc.to_string e in
            Cert_callback.register callback false msg None None false
      in
      match callback_result with
      | Error (`Capnp e) ->
          Eio.traceln "Error calling callback %a" Capnp_rpc.Error.pp e;
          Service.fail "No callback parameter!"
      | Ok () -> Service.return @@ Service.Response.create_empty ())
