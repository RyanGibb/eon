let get_log log_level =
  (match log_level with
  | 0 -> Dns_log.log_level_0
  | 1 -> Dns_log.log_level_1
  | 2 -> Dns_log.log_level_2
  | 3 -> Dns_log.log_level_3
  | _ -> if log_level < 0 then Dns_log.log_level_0 else Dns_log.log_level_2)
    Format.std_formatter

let parse_addresses port addressStrings =
  List.map
    (fun ip ->
      match Ipaddr.with_port_of_string ~default:port ip with
      | Ok (ip, p) ->
          let eioIp = Ipaddr.to_octets ip |> Eio.Net.Ipaddr.of_raw in
          (eioIp, p)
      | Error (`Msg msg) ->
          Format.fprintf Format.err_formatter "Error parsing address '%s': %s"
            ip msg;
          exit 1)
    addressStrings

let run zonefiles log_level addressStrings domain subdomain port no_tcp no_udp
    enable_server nameserver =
  if no_tcp && no_udp then (
    Format.fprintf Format.err_formatter "Either UDP or TCP should be enabled\n";
    Format.pp_print_flush Format.err_formatter ();
    exit 1);
  let tcp = not no_tcp and udp = not no_udp in
  Eio_main.run @@ fun env ->
  let log = get_log log_level in
  Eio.Switch.run @@ fun sw ->
  if enable_server then
    let addresses = parse_addresses port addressStrings in
    let server_state =
      let trie, keys = Zonefile.parse_zonefiles ~fs:env#fs zonefiles in
      let rng ?_g length =
        let buf = Cstruct.create length in
        Eio.Flow.read_exact env#secure_random buf;
        buf
      in
      ref
      @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
           ~tsig_sign:Dns_tsig.sign trie
    in
    let server =
      Transport.dns_server ~sw ~net:env#net ~clock:env#clock
        ~mono_clock:env#mono_clock ~tcp ~udp subdomain server_state log
        addresses
    in
    Eio.Flow.copy server server
  else
    let client =
      Transport.dns_client ~sw ~net:env#net ~clock:env#clock
        ~random:env#secure_random nameserver subdomain domain port log
    in
    Eio.Fiber.both
      (fun () -> Eio.Flow.copy env#stdin client)
      (fun () -> Eio.Flow.copy client env#stdout)

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
    let server =
      let doc = "Whether to enable server mode" in
      Arg.(value & flag & info [ "s"; "server" ] ~docv:"SERVER" ~doc)
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
        const run $ zonefiles $ logging_default 0 $ addresses $ domain
        $ subdomain $ port $ no_tcp $ no_udp $ server $ nameserver)
    in
    let info = Cmd.info "netcat" ~man in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
