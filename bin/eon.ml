let run zonefiles log_level addressStrings port proto resolver =
  Eio_main.run @@ fun env ->
  let addresses = Server_args.parse_addresses port addressStrings in
  let log = log_level Format.std_formatter in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact env#secure_random buf;
    buf
  in
  let server_state =
    let trie, keys = Zonefile.parse_zonefiles ~fs:env#fs zonefiles in
    Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
        ~tsig_sign:Dns_tsig.sign trie
  in
  if resolver then
    let resolver_state =
      let now = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
      Dns_resolver.create ~cache_size:29 ~dnssec:false ~ip_protocol:`Ipv4_only
          now rng server_state
    in
    Dns_resolver_eio.resolver ~net:env#net ~clock:env#clock
      ~mono_clock:env#mono_clock ~proto (ref resolver_state) log addresses
  else
    Dns_server_eio.primary ~net:env#net ~clock:env#clock
      ~mono_clock:env#mono_clock ~proto (ref server_state) log addresses

let () =
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.level_0 $ addresses $ port $ proto $ resolver)
    in
    let info = Cmd.info "eon" ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
