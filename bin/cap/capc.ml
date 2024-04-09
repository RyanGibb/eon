let run_client env email org domain cert_root cap =
  let domain_cap = Cap.Zone.init cap domain in
  (* callback for provisioned cert *)
  let cert_callback_cap =
    Cap.Cert_callback.local (fun result ->
        match result with
        | Error (`Cert msg) ->
            Printf.eprintf "%s%!" msg;
            Unix._exit 1
        | Error (`Capnp e) ->
            Format.printf "%a%!" Capnp_rpc.Error.pp e;
            Unix._exit 1
        | Ok (cert, key) ->
            let write_pem filepath pem = Eio.Path.save ~create:(`Or_truncate 0o600) filepath pem in
            Eio.Switch.run @@ fun sw ->
            let ( / ) = Eio.Path.( / ) in
            let cert_dir = env#fs / cert_root / Domain_name.to_string domain in
            Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 cert_dir;
            let private_key_file = cert_dir / "privkey.pem" in
            let cert_file = cert_dir / "fullcert.pem" in
            write_pem private_key_file key;
            write_pem cert_file cert;
            Printf.printf "Updated cert for %s\n%!" (Domain_name.to_string domain))
  in
  match Cap.Domain.cert domain_cap ~email ~org ~subdomain:Domain_name.root cert_callback_cap with
  | Error (`Capnp e) -> Format.eprintf "%a" Capnp_rpc.Error.pp e
  | Ok () -> ()

let run email org domain cap_uri cap_uri_file cert_root =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let uri =
    match cap_uri with Some c -> c | None -> Uri.of_string (Eio.Path.load Eio.Path.(Eio.Stdenv.fs env / cap_uri_file))
  in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat uri
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref (run_client env email org domain cert_root)

let () =
  let open Cmdliner in
  let cmd =
    let cap_uri =
      let doc =
        "Capability URI of the format capnp://sha-256:<hash>@address:port/<service-ID>. Takes priority over cap-file."
      in
      let i = Arg.info [ "cap" ] ~docv:"CAP" ~doc in
      Arg.(value @@ opt (some Capnp_rpc_unix.sturdy_uri) None i)
    in
    let cap_uri_file =
      let doc =
        "File path containing the capability URI of the format capnp://sha-256:<hash>@address:port/<service-ID>."
      in
      Arg.(value & opt string "root.cap" & info [ "cap-file" ] ~docv:"CAP_FILE" ~doc)
    in
    let email =
      let doc = "The email address to use for the ACME account." in
      Arg.(required & pos 1 (some string) None & info [] ~docv:"EMAIL" ~doc)
    in
    let domain =
      let doc = "The domain for which to request the certificate." in
      Arg.(required & pos 2 (some (conv (Domain_name.of_string, Domain_name.pp))) None & info [] ~docv:"DOMAIN" ~doc)
    in
    let org =
      let doc = "The name of the organization requesting the certificate." in
      Arg.(value & opt string "" & info [ "org" ] ~docv:"ORGANIZATION" ~doc)
    in
    let cert_root =
      let doc = "Directory to store the certificates and keys in at path <cert-root>/<domain>/." in
      Arg.(value & opt string "certs" & info [ "cert-root" ] ~doc)
    in
    let term = Term.(const run $ email $ org $ domain $ cap_uri $ cap_uri_file $ cert_root) in
    let doc = "Let's Encrypt Nameserver Client." in
    let info = Cmd.info "cap" ~doc in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
