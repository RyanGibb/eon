let cap_file = "cert.cap"

let capnp_serve env config provision =
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let service_id = Capnp_rpc_unix.Vat_config.derived_id config "main" in
  let restore = Capnp_rpc_net.Restorer.single service_id (Service.Root.local provision) in
  let vat = Capnp_rpc_unix.serve ~sw ~net:env#net ~restore config in
  match Capnp_rpc_unix.Cap_file.save_service vat service_id cap_file with
  | Error `Msg m -> failwith m
  | Ok () ->
    Eio.traceln "Server running. Connect using %S." cap_file;
    Eio.Fiber.await_cancel ()

let run zonefiles log_level addressStrings port proto prod authorative capnp_config =
  Eio_main.run @@ fun env ->
  let log = log_level Format.std_formatter in
  let addresses = Server_args.parse_addresses port addressStrings in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact env#secure_random buf;
    buf
  in
  let server_state =
    let trie, keys = Zonefile.parse_zonefiles ~fs:env#fs zonefiles in
    let trie = match authorative with
    | None -> trie
    | Some authorative -> Dns_trie.insert Domain_name.root Dns.Rr_map.Soa (Dns.Soa.create authorative) trie in
    ref
    @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
         ~tsig_sign:Dns_tsig.sign trie
  in
  Eio.Switch.run @@ fun sw ->
  Eio.Fiber.fork ~sw (fun () -> Dns_server_eio.primary ~net:env#net ~clock:env#clock
    ~mono_clock:env#mono_clock ~proto server_state log addresses);
  
  let provision = Dns_acme.provision_cert prod server_state env in
  capnp_serve env capnp_config provision

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs_fmt.reporter ());
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let prod =
      let doc = "Production certification generation" in
      Arg.(value & flag & info [ "prod" ] ~doc)
    in
    let authorative =
      let doc =
        "Domain(s) for which the nameserver is authorative for, if not passed in zonefiles."
      in
      Arg.(value & opt (some (conv (Domain_name.of_string, Domain_name.pp))) None & info [ "a"; "authorative" ] ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.level_1 $ addresses $ port $ proto $ prod $ authorative $ Capnp_rpc_unix.Vat_config.cmd)
    in
    let doc = "Let's Encrypt Nameserver Daemon" in
    let info = Cmd.info "lend" ~doc ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
