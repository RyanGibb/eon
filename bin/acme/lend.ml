let handle_client env prod cert server_state sock =
  let buffer = Eio.Buf_read.of_flow ~max_size:4096 sock in
  let email = Eio.Buf_read.line buffer in
  let org = Eio.Buf_read.line buffer in
  let domain = Eio.Buf_read.line buffer in
  Eio.Flow.shutdown sock `Receive;

  let acmeName = ref @@ None in
  let solver =
    let add_record name record =
      let (let*) = Result.bind in

      (* vertify that the name provided in the ACME server challenge begins with `_acme-challenge` *)
      let verify_name name =
        let labels = Domain_name.to_array name in
        match Array.length labels > 0 && labels.(Array.length labels - 1) = "_acme-challenge" with
        | false -> Error (`Msg "error")
        | true -> Ok ()
      in
      let* _ = verify_name name in

      (* get the nameserver trie *)
      let trie = Dns_server.Primary.data !server_state in

      (* check if there's any issues adding a record for this name *)
      let* trie = match Dns_trie.lookup name Dns.Rr_map.Txt trie with
      (* if there is no record, all is well *)
      | Error `NotFound _ -> Ok trie
      (* if there is a record, let's remove it to be prudent *)
      | Ok (ttl, records) ->
        let trie = Dns_trie.remove_ty name Dns.Rr_map.Txt trie in
        Dns.Rr_map.Txt_set.iter (fun record ->
          Eio.traceln "Remove '%a %ld IN TXT \"%s\"'" Domain_name.pp name ttl record;
        ) records;
        Ok trie;
      (* if there's any other issues, like the server is not authorative for this zone, or the zone has been delegated *)
      | Error e ->
        Eio.traceln "Error with ACME CSR name '%a': %a" Domain_name.pp name Dns_trie.pp_e e;
        let msg = Format.asprintf "%a" Dns_trie.pp_e e in
        Error (`Msg msg)
      in

      (* 1 hour is a sensible TTL *)
      let ttl = 3600l in
      let rr =
        ttl, Dns.Rr_map.Txt_set.singleton record
      in
      let trie = Dns_trie.insert name Dns.Rr_map.Txt rr trie in
      (* TODO send out notifications for secondary nameservers *)
      let new_server_state, _notifications =
        let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
        and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
        Dns_server.Primary.with_data !server_state now ts trie in
      server_state := new_server_state;
      acmeName := Some name;
      Eio.traceln "Create '%a %ld IN TXT \"%s\"'" Domain_name.pp name ttl record;
      (* we could wait for dns propigation here...
         but we hope that a new un-cached record is created
         and if not, the server should retry (RFC 8555 S8.2) *)
      Ok ()
    in
    Letsencrypt_dns.dns_solver add_record
  in

  let endpoint = if prod then Letsencrypt.letsencrypt_production_url else Letsencrypt.letsencrypt_staging_url in
  Eio.Switch.run @@ fun sw ->
  let cert_root = let ( / ) = Eio.Path.( / ) in Eio.Path.open_dir ~sw (env#fs / cert) in
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  try
    ignore @@ Tls_le.tls_config ~cert_root ~org ~email ~domain ~endpoint ~solver env;
    Eio.Flow.copy_string cert sock;
    Eio.Flow.shutdown sock `All
  with Tls_le.Le_error msg -> (
      Eio.Flow.copy_string ("Error: " ^ msg) sock;
      Eio.traceln "ACME error: %s" msg;
      Eio.Flow.shutdown sock `All
  );
  (* once cert provisioned, remove the record *)
  match !acmeName with
  | None -> ()
  | Some name ->
    let trie = Dns_server.Primary.data !server_state in
    match Dns_trie.lookup name Dns.Rr_map.Txt trie with
    | Error e -> Eio.traceln "Error removing %a from trie: %a" Domain_name.pp name Dns_trie.pp_e e;
    | Ok (ttl, records) ->
      let data = Dns_trie.remove_ty name Dns.Rr_map.Txt trie in
      (* TODO send out notifications *)
      let new_server_state, _notifications =
        let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
        and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
        Dns_server.Primary.with_data !server_state now ts data in
      server_state := new_server_state;
      Dns.Rr_map.Txt_set.iter (fun record ->
        Eio.traceln "Remove '%a %ld IN TXT \"%s\"'" Domain_name.pp name ttl record;
      ) records;
    ()

let run zonefiles log_level addressStrings port proto prod cert socket_path =
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
    ref
    @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
         ~tsig_sign:Dns_tsig.sign trie
  in

  Eio.Switch.run @@ fun sw ->
  Eio.Fiber.fork ~sw (fun () -> Dns_server_eio.primary ~net:env#net ~clock:env#clock
    ~mono_clock:env#mono_clock ~proto server_state log addresses);

  let socket = Eio.Net.listen ~backlog:128 ~sw env#net (`Unix socket_path) in
  while true do
    let sock, _addr = Eio.Net.accept ~sw socket in
    Eio.Fiber.fork ~sw (fun () -> handle_client env prod cert server_state sock)
  done

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Info);
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let prod =
      let doc = "Production certification generation" in
      Arg.(value & flag & info [ "prod" ] ~doc)
    in
    let cert =
      let doc = "Directory where to store the certificates" in
      Arg.(value & opt string "certs" & info [ "certs-dir" ] ~doc)
    in
    let socket_path =
      let doc = "The path to the Unix domain socket." in
      Arg.(value & opt string "/run/lend/cert.socket" & info ["s"; "socket"] ~docv:"SOCKET_PATH" ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.level_1 $ addresses $ port $ proto $ prod $ cert $ socket_path)
    in
    let doc = "Let's Encrypt Nameserver Daemon" in
    let info = Cmd.info "lend" ~doc ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
