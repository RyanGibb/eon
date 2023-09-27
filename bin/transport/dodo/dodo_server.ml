let run zonefiles log_level addressStrings domain subdomain port no_tcp no_udp =
  if no_tcp && no_udp then (
    Format.fprintf Format.err_formatter "Either UDP or TCP should be enabled\n";
    Format.pp_print_flush Format.err_formatter ();
    exit 1);
  let tcp = not no_tcp and udp = not no_udp in
  let log = (Dns_log.get_log log_level) Format.std_formatter in
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
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

  let server =
    Transport.dns_server_datagram ~sw ~net:env#net ~clock:env#clock
      ~mono_clock:env#mono_clock ~tcp ~udp subdomain domain server_state log
      addresses
  in

  let resolver_state =
    let now = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
    ref
    @@ Dns_resolver.create ~cache_size:29 ~dnssec:false ~ip_protocol:`Ipv4_only
         now rng !server_state
  in
  Eio.Fiber.fork ~sw (fun () -> Dns_resolver_eio.resolver ~net:env#net ~clock:env#clock
  ~mono_clock:env#mono_clock ~tcp ~udp resolver_state (Dns_log.log_level_1 Format.std_formatter) [ Eio.Net.Ipaddr.V4.any, 5056 ]);

  let clientSock =
    Eio.Net.datagram_socket ~sw env#net `UdpV4
  in
  Eio.Fiber.both
    (fun () ->
      let buf = Cstruct.create 4096 in
      while true do
        let got = server#recv buf in
        let trimmedBuf = Cstruct.sub buf 0 got in
        Dns_log.log_level_1 Format.std_formatter Dns_log.Rx (`Unix "tunneled") trimmedBuf;
        Eio.Net.send clientSock (`Udp (Eio.Net.Ipaddr.V4.loopback, 5056)) buf;
      done)
    (fun () ->
      let buf = Cstruct.create 4096 in
      while true do
        let addr, size = Eio.Net.recv clientSock buf in
        let trimmedBuf = Cstruct.sub buf 0 size in
        Dns_log.log_level_1 Format.std_formatter Dns_log.Tx (`Unix "tunneled") trimmedBuf;
        server#send trimmedBuf
      done)

let () =
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let domain =
      let doc = "Domain that the NAMESERVER is authorative for." in
      Arg.(
        value & opt string "example.org"
        & info [ "d"; "domain" ] ~docv:"DOMAIN" ~doc)
    in
    let subdomain =
      let doc =
        "Sudomain to use custom processing on. This will be combined with the \
         root DOMAIN to form <SUBDOMAIN>.<DOMAIN>, e.g. rpc.example.org. Data \
         will be encoded as a base 64 string as a sudomain of this domain \
         giving <DATA>.<SUBDOMAIN>.<DOMAIN>, e.g. aGVsbG8K.rpc.example.org."
      in
      Arg.(
        value & opt string "rpc"
        & info [ "sd"; "subdomain" ] ~docv:"SUBDOMAIN" ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ logging $ addresses $ domain $ subdomain $ port $ no_tcp
        $ no_udp)
    in
    let doc = "An authorative nameserver using OCaml 5 effects-based IO" in
    let info = Cmd.info "netcatd" ~man ~doc in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
