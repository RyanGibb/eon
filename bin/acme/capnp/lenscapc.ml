let run_client email org domain cert_cap =
  let account_key = Tls_le.gen_account_key () |> X509.Private_key.encode_pem |> Cstruct.to_string in
  let private_key = Tls_le.gen_private_key () |> X509.Private_key.encode_pem |> Cstruct.to_string in
  match Cert.request cert_cap ~account_key ~private_key ~email ~org ~domain with
  | Error (`Cert msg) ->
    Format.fprintf Format.std_formatter "%s" msg
  | Error (`Capnp e) ->
    Format.fprintf Format.err_formatter "%a" Capnp_rpc.Error.pp e
  | Ok cert ->
    Format.fprintf Format.err_formatter  "%s" cert

let run email org domain connect_addr =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
  let sr = Capnp_rpc_unix.Vat.import_exn client_vat connect_addr in
  Capnp_rpc_unix.with_cap_exn sr (run_client email org domain)

let () =
let open Cmdliner in
  let cmd =
    let connect_addr =
      let i = Arg.info [] ~docv:"ADDR" ~doc:"Address of server (capnp://...)" in
      Arg.(required @@ pos 0 (some Capnp_rpc_unix.sturdy_uri) None i)
    in
    let email =
      let doc = "The email address to use for the ACME account." in
      Arg.(required & pos 1 (some string) None & info [] ~docv:"EMAIL" ~doc)
    in
    let org =
      let doc = "The name of the organization requesting the certificate." in
      Arg.(required & pos 2 (some string) None & info [] ~docv:"ORGANIZATION" ~doc)
    in
    let domain =
      let doc = "The domain for which to request the certificate." in
      Arg.(required & pos 3 (some string) None & info [] ~docv:"DOMAIN" ~doc)
    in
    let term = Term.(const run $ email $ org $ domain $ connect_addr) in
    let doc = "Let's Encrypt Nameserver Client." in
    let info = Cmd.info "lenc" ~doc in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
