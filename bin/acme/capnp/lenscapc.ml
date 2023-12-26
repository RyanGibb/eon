let run_client email org domain cap =
  let domain_cap = Service.Root.bind cap domain in
  (* callback for provisioned cert *)
  let mgr_cap = Service.CertManager.local (fun result ->
    match result with
    | Error (`Cert msg) ->
      Printf.eprintf "%s%!" msg;
      Unix._exit 1
    | Error (`Capnp e) ->
      Format.printf "%a%!" Capnp_rpc.Error.pp e;
      Unix._exit 1
    | Ok (cert, key) ->
      Printf.printf "%s\n%s%!" cert key
  ) in
  match Service.Domain.cert domain_cap ~email ~org ~subdomain:Domain_name.root mgr_cap with
    | Error (`Capnp e) ->
      Format.eprintf "%a" Capnp_rpc.Error.pp e
    | Ok () -> ()

let run email org domain connect_addr =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
  let sr = Capnp_rpc_unix.Vat.import_exn client_vat connect_addr in
  Capnp_rpc_unix.with_cap_exn sr (run_client email org domain) ~progress:`Log

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
      Arg.(required & pos 3 (some (conv (Domain_name.of_string, Domain_name.pp))) None & info [] ~docv:"DOMAIN" ~doc)
    in
    let term = Term.(const run $ email $ org $ domain $ connect_addr) in
    let doc = "Let's Encrypt Nameserver Client." in
    let info = Cmd.info "lenc" ~doc in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
