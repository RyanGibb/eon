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

let run zonefiles log_level addressStrings data_subdomain port tcp udp =
  Eio_main.run @@ fun env ->
  let log = get_log log_level in
  let addresses = parse_addresses port addressStrings in
  let server =
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
  Eio.Switch.run @@ fun sw ->
  let server =
    Transport.dns_server ~sw ~net:env#net ~clock:env#clock
      ~mono_clock:env#mono_clock ~tcp ~udp data_subdomain server log addresses
  in
  let client =
    Transport.dns_client ~sw ~net:env#net "127.0.0.1" data_subdomain
      "example.org" port log
  in
  Eio.Fiber.all
    [
      (fun () -> Eio.Flow.copy env#stdin client);
      (fun () -> Eio.Flow.copy server server);
      (fun () -> Eio.Flow.copy client env#stdout);
    ]

let cmd =
  let zonefiles =
    Cmdliner.Arg.(
      value & opt_all string []
      & info [ "z"; "zonefile" ] ~docv:"ZONEFILE_PATHS" ~doc:"Zonefile path.")
  in
  let logging =
    Cmdliner.Arg.(
      value & opt int 1
      & info [ "l"; "log-level" ] ~docv:"LOG_LEVEL" ~doc:"Log level.")
  in
  let data_subdomain =
    Cmdliner.Arg.(
      value & opt string "rpc"
      & info [ "d"; "data-subdomain" ] ~docv:"DATA_SUBDOMAIN"
          ~doc:"Data subdomain.")
  in
  let port =
    Cmdliner.Arg.(
      value & opt int 53 & info [ "p"; "port" ] ~docv:"PORT" ~doc:"Port.")
  in
  let addresses =
    let doc =
      "IP addresses to bind too.
      
      By default `in6addr_any` '::' is used. If IPv4-mapped IPv6 (RFC3493) is not
      supported, e.g. on OpenBSD, the user will need to specify an IPv4 address
      in order to serve IPv4 traffic, e.g. `-a 127.0.0.1 -a '::'`.
      
      A can be specified, e.g. with `[::]:5053`, otherwise the default
      `port` is used.

      NB names, e.g. `localhost`, are not supported."
    in
    Cmdliner.Arg.(
      (* :: is IPv6 local *)
      value & opt_all string [ "::" ]
      & info [ "a"; "address" ] ~docv:"ADDRESSES" ~doc)
  in
  let tcp =
    let doc = "Whether to use TCP." in
    Cmdliner.Arg.(value & opt bool true & info [ "t"; "tcp" ] ~docv:"TCP" ~doc)
  in
  let udp =
    let doc = "Whether to use UDP." in
    Cmdliner.Arg.(value & opt bool true & info [ "u"; "udp" ] ~docv:"UDP" ~doc)
  in
  let dns_t =
    Cmdliner.Term.(
      const run $ zonefiles $ logging $ addresses $ data_subdomain $ port $ tcp
      $ udp)
  in
  let info = Cmdliner.Cmd.info "dns" in
  Cmdliner.Cmd.v info dns_t

let () =
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
