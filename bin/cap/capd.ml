let register_secondary env ~sw primary_uri_files primary_retry_wait
    persist_new_secondary =
  let initial_primaries =
    List.map
      (fun primary_uri_file ->
        let primary_uri =
          Uri.of_string
            (Eio.Path.load Eio.Path.(Eio.Stdenv.fs env / primary_uri_file))
        in
        let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
        Capnp_rpc_unix.Vat.import_exn client_vat primary_uri)
      primary_uri_files
  in
  let rec register primaries =
    match
      List.fold_left
        (fun retry primary ->
          match
            let ( let* ) = Result.bind in
            let* name =
              Capnp_rpc_unix.with_cap_exn primary Cap.Primary.get_name
            in
            match persist_new_secondary ~name with
            | Error e ->
                Capnp_rpc.Exception.pp Format.err_formatter e;
                ignore @@ failwith "Failed to create secondary";
                Ok ()
            | Ok secondary ->
                ignore
                @@ Capnp_rpc_unix.with_cap_exn primary
                     (Cap.Primary.register_secondary ~secondary);
                Ok ()
          with
          | exception Failure e ->
              Eio.traceln "Failed to connnect to primary: %s" e;
              Eio.traceln "Retrying in %f" primary_retry_wait;
              primary :: retry
          | Error (`Capnp e) ->
              Eio.traceln "Failed to connnect to primary: %a%!"
                Capnp_rpc.Error.pp e;
              retry
          | Error (`Remote e) ->
              Eio.traceln "Remote Error registering to primary: %s%!" e;
              retry
          | Ok () -> retry)
        [] primaries
    with
    | [] -> ()
    | retry ->
        Eio.Time.sleep env#clock primary_retry_wait;
        register retry
  in
  Eio.Fiber.fork ~sw (fun () -> register initial_primaries)

let capnp_serve env authorative vat_config prod endpoint server_state state_dir
    primary_uri_files primary_retry_wait =
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let cap_dir = Eio.Path.(env#fs / state_dir / "caps") in
  let domain_dir = Eio.Path.(cap_dir / "domain") in
  let primary_dir = Eio.Path.(cap_dir / "primary") in
  let secondary_dir = Eio.Path.(cap_dir / "secondary") in
  let store_dir = Eio.Path.(env#fs / state_dir / "store") in
  List.iter
    (fun d -> Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 d)
    [ cap_dir; domain_dir; primary_dir; secondary_dir; store_dir ];

  let get_domain_id name =
    Capnp_rpc_unix.Vat_config.derived_id vat_config name
  in
  let get_primary_id name =
    Capnp_rpc_unix.Vat_config.derived_id vat_config ("primary_" ^ name)
  in

  let loader, set_domain_loader, set_secondary_loader =
    let make_sturdy = Capnp_rpc_unix.Vat_config.sturdy_uri vat_config in
    Cap.Db.create ~make_sturdy store_dir
  in
  Eio.Switch.run @@ fun sw ->
  let services =
    Capnp_rpc_net.Restorer.Table.of_loader ~sw (module Cap.Db) loader
  in
  let restore = Capnp_rpc_net.Restorer.of_table services in
  let persist_new_domain ~name primary =
    let id = Cap.Db.save_new_domain loader ~name primary in
    Capnp_rpc_net.Restorer.restore restore id
  in
  let persist_new_secondary ~name =
    let id = Cap.Db.save_new_secondary loader ~name in
    Capnp_rpc_net.Restorer.restore restore id
  in
  Eio.Std.Promise.resolve set_domain_loader (fun sr ~name ~primary ->
      let id = get_primary_id primary in
      match Capnp_rpc_net.Restorer.restore restore id with
      | Ok primary ->
          Capnp_rpc_net.Restorer.grant
          @@ Cap.Domain.local ~sw ~persist_new_domain sr env name prod endpoint
               server_state state_dir primary
      | Error _ -> Capnp_rpc_net.Restorer.unknown_service_id);
  Eio.Std.Promise.resolve set_secondary_loader (fun sr ~name ->
      Capnp_rpc_net.Restorer.grant
      @@ Cap.Secondary.local sr env name server_state);

  let vat = Capnp_rpc_unix.serve ~sw ~net:env#net ~restore vat_config in

  List.iter
    (fun domain ->
      let name = Domain_name.to_string domain in

      let secondary_domain_dir = Eio.Path.(secondary_dir / name) in
      Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 secondary_domain_dir;

      let secondaries =
        let filenames = Eio.Path.(read_dir secondary_domain_dir) in
        List.fold_left
          (fun acc filename ->
            let _, filepath = Eio.Path.(secondary_domain_dir / filename) in
            match Capnp_rpc_unix.Cap_file.load vat filepath with
            | Error (`Msg m) ->
                Eio.traceln "Couldn't connect to secondary at %s: %s" filepath m;
                acc
            | Ok cap -> (
                try Capnp_rpc_lwt.Sturdy_ref.connect_exn cap :: acc
                with Failure m ->
                  Eio.traceln "Couldn't connect to secondary at %s: %s" filepath
                    m;
                  acc))
          [] filenames
      in

      let domain_id = get_domain_id name in
      let primary_id = get_primary_id name in
      let domain_sr =
        Capnp_rpc_net.Restorer.Table.sturdy_ref services domain_id
      in
      let primary_sr =
        Capnp_rpc_net.Restorer.Table.sturdy_ref services primary_id
      in

      let primary =
        Cap.Primary.local primary_sr domain server_state secondaries
          secondary_domain_dir
      in
      let domain =
        Cap.Domain.local ~sw ~persist_new_domain domain_sr env domain prod
          endpoint server_state state_dir primary
      in
      Capnp_rpc_net.Restorer.Table.add services domain_id domain;
      Capnp_rpc_net.Restorer.Table.add services primary_id primary;
      let _, domain_file = Eio.Path.(domain_dir / (name ^ ".cap")) in
      (match Capnp_rpc_unix.Cap_file.save_service vat domain_id domain_file with
      | Error (`Msg m) -> failwith m
      | Ok () -> ());
      let _, primary_file = Eio.Path.(cap_dir / "primary" / (name ^ ".cap")) in
      (match
         Capnp_rpc_unix.Cap_file.save_service vat primary_id primary_file
       with
      | Error (`Msg m) -> failwith m
      | Ok () -> ());
      Printf.printf "Saved %S\n" name)
    authorative;
  register_secondary env ~sw primary_uri_files primary_retry_wait
    persist_new_secondary

let run zonefiles log_level address_strings port proto prod endpoint authorative
    state_dir primary_uri_files primary_retry_wait vat_config =
  Eio_main.run @@ fun env ->
  let log = Dns_log.get log_level Format.std_formatter in
  let addresses = Server_args.parse_addresses port address_strings in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact env#secure_random buf;
    buf
  in
  let trie', _keys, parsedAuthorative =
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
    @@ Dns_server.Primary.create ~keys:[] ~rng ~tsig_verify:Dns_tsig.verify
         ~tsig_sign:Dns_tsig.sign trie
  in
  Eio.Switch.run @@ fun sw ->
  Eio.Fiber.fork ~sw (fun () ->
      Dns_server_eio.primary env proto server_state log addresses);
  Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 Eio.Path.(env#fs / state_dir);
  capnp_serve env authorative vat_config prod endpoint server_state state_dir
    primary_uri_files primary_retry_wait;
  Eio.Fiber.await_cancel ()

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
    let primary_uri_files =
      let doc =
        "File paths containing primary capability URIs of the format \
         capnp://sha-256:<hash>@address:port/<service-ID> that this nameserver \
         will register as secondary of."
      in
      Arg.(
        value & opt_all string [] & info [ "primary" ] ~docv:"SECONDARY" ~doc)
    in
    let primary_retry_wait =
      let doc =
        "Seconds to wait between retrying connecting to a primary upon failure."
      in
      Arg.(
        value & opt float 60.
        & info [ "primary-retry-wait" ] ~docv:"PRIMAR_RETRY_WAIT" ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.Level1 $ addresses $ port
        $ proto $ prod $ endpoint $ authorative $ state_dir $ primary_uri_files
        $ primary_retry_wait $ Capnp_rpc_unix.Vat_config.cmd)
    in
    let doc = "Let's Encrypt Nameserver Daemon" in
    let info = Cmd.info "cap" ~doc ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
