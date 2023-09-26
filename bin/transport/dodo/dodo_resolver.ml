let run log_level addressStrings port no_tcp no_udp domain subdomain nameserver
    =
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

  Eio.Fiber.fork ~sw (fun () ->
      let server_state =
        Dns_server.Primary.create ~keys:[] ~rng ~tsig_verify:Dns_tsig.verify
          ~tsig_sign:Dns_tsig.sign Dns_trie.empty
      in
      let resolver_state =
        let now = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
        ref
        @@ Dns_resolver.create ~cache_size:29 ~dnssec:false
             ~ip_protocol:`Ipv4_only now rng server_state
      in
      Dns_resolver_eio.resolver ~net:env#net ~clock:env#clock
        ~mono_clock:env#mono_clock ~tcp ~udp resolver_state log addresses);
  let client =
    Transport.dns_client_stream ~sw ~net:env#net ~clock:env#clock
      ~random:env#secure_random nameserver subdomain domain port log
  in
  Eio.Fiber.both
    (fun () -> Eio.Flow.copy env#stdin client)
    (fun () -> Eio.Flow.copy client env#stdout)

(* recv query
   get data
   run transport layer to tunnel query to server *)

let () =
  let open Cmdliner in
  let open Server_args in
  let cmd =
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
    let domain =
      let doc = "Domain that the NAMESERVER is authorative for." in
      Arg.(
        value & opt string "example.org"
        & info [ "d"; "domain" ] ~docv:"DOMAIN" ~doc)
    in
    let nameserver =
      let doc =
        "The address of the nameserver to query. The first result returned by \
         getaddrinfo will be used. If this may return multiple values, e.g. an \
         IPv4 and IPv6 address for a host, and a specific one is desired it \
         should be specified."
      in
      Arg.(
        value & opt string "127.0.0.1"
        & info [ "n"; "nameserver" ] ~docv:"NAMESERVER" ~doc)
    in
    let term =
      Term.(
        const run $ logging_default 0 $ addresses $ port $ no_tcp $ no_udp
        $ domain $ subdomain $ nameserver)
    in
    let doc = "An authorative nameserver using OCaml 5 effects-based IO" in
    let info = Cmd.info "netcat" ~man ~doc in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
