let capnp_serve env authorative vat_config prod endpoint server_state state_dir
    =
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let cap_dir = Eio.Path.(env#fs / state_dir / "caps") in
  Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 cap_dir;

  let make_sturdy = Capnp_rpc_unix.Vat_config.sturdy_uri vat_config in
  let store_dir = Eio.Path.(env#fs / state_dir / "store") in
  Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 store_dir;
  let db, set_loader = Cap.Db.create ~make_sturdy store_dir in
  let services =
    Capnp_rpc_net.Restorer.Table.of_loader ~sw (module Cap.Db) db
  in
  let restore = Capnp_rpc_net.Restorer.of_table services in
  let persist_new ~name =
    let id = Cap.Db.save_new db ~name in
    Capnp_rpc_net.Restorer.restore restore id
  in
  Eio.Std.Promise.resolve set_loader (fun sr ~name ->
      Capnp_rpc_net.Restorer.grant
      @@ Cap.Domain.local ~sw ~persist_new sr env name prod endpoint
           server_state state_dir);
  let vat = Capnp_rpc_unix.serve ~sw ~net:env#net ~restore vat_config in

  let zone_cap =
    Cap.Zone.local ~sw ~persist_new vat_config services env prod endpoint
      server_state state_dir
  in
  let _zone =
    let id = Capnp_rpc_unix.Vat_config.derived_id vat_config "zone" in
    Capnp_rpc_net.Restorer.Table.add services id zone_cap;
    let _, file = Eio.Path.(cap_dir / "zone.cap") in
    (match Capnp_rpc_unix.Cap_file.save_service vat id file with
    | Error (`Msg m) -> failwith m
    | Ok () -> ());
    (* todo chgrp acme-eon caps dir *)
    Printf.printf "[server] saved %S\n" file
  in

  List.iter
    (fun domain ->
      let name = Domain_name.to_string domain in
      let id = Capnp_rpc_unix.Vat_config.derived_id vat_config name in
      let cap = Cap.Zone.init zone_cap domain in
      Capnp_rpc_net.Restorer.Table.add services id cap;
      let _, file = Eio.Path.(cap_dir / (name ^ ".cap")) in
      (match Capnp_rpc_unix.Cap_file.save_service vat id file with
      | Error (`Msg m) -> failwith m
      | Ok () -> ());
      Printf.printf "[server] saved %S\n" file)
    authorative;

  Eio.Fiber.await_cancel ()

let run zonefiles log_level addressStrings port proto prod endpoint authorative
    state_dir vat_config =
  Eio_main.run @@ fun env ->
  let log = Dns_log.get log_level Format.std_formatter in
  let addresses = Server_args.parse_addresses port addressStrings in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact env#secure_random buf;
    buf
  in
  let trie', keys, parsedAuthorative =
    Zonefile.parse_zonefiles ~fs:env#fs zonefiles
  in
  let trie =
    List.fold_left
      (fun trie domain ->
        Dns_trie.insert Domain_name.root Dns.Rr_map.Soa (Dns.Soa.create domain)
          trie)
      trie' authorative
  in
  (* join authorative domains to those specified on the command line *)
  let authorative = parsedAuthorative @ authorative in
  let server_state =
    ref
    @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
         ~tsig_sign:Dns_tsig.sign trie
  in
  Eio.Switch.run @@ fun sw ->
  Eio.Fiber.fork ~sw (fun () ->
      Dns_server_eio.primary env proto server_state log addresses);
  Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 Eio.Path.(env#fs / state_dir);
  capnp_serve env authorative vat_config prod endpoint server_state state_dir

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs_fmt.reporter ());
  (* Logs.Src.set_level Capnp_rpc.Debug.src (Some Logs.Debug); *)
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let prod =
      let doc = "Production certification generation" in
      Arg.(value & flag & info [ "prod" ] ~doc)
    in
    let endpoint =
      let doc =
        "ACME Directory Resource URI. Defaults to Let's Encrypt's staging \
         endpoint https://acme-staging-v02.api.letsencrypt.org/directory, or \
         if --prod set Let's Encrypt's production endpoint \
         https://acme-v02.api.letsencrypt.org/directory."
      in
      let i = Arg.info [ "cap" ] ~docv:"CAP" ~doc in
      Arg.(
        value
        @@ opt
             (some
                (Cmdliner.Arg.conv
                   ( (fun s ->
                       match Uri.of_string s with
                       | exception ex ->
                           Error
                             (`Msg
                               (Fmt.str "Failed to parse URI %S: %a" s Fmt.exn
                                  ex))
                       | uri -> Ok uri),
                     Uri.pp_hum )))
             None i)
    in
    let authorative =
      let doc =
        "Domain(s) for which the nameserver is authorative for, if not passed \
         in zonefiles."
      in
      Arg.(
        value
        & opt_all (conv (Domain_name.of_string, Domain_name.pp)) []
        & info [ "a"; "authorative" ] ~docv:"AUTHORATIVE" ~doc)
    in
    let state_dir =
      let doc =
        "Directory to state such as account keys, sturdy refs, and \
         certificates."
      in
      Arg.(value & opt string "state" & info [ "state-dir" ] ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.Level1 $ addresses $ port
        $ proto $ prod $ endpoint $ authorative $ state_dir
        $ Capnp_rpc_unix.Vat_config.cmd)
    in
    let doc = "Let's Encrypt Nameserver Daemon" in
    let info = Cmd.info "cap" ~doc ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
