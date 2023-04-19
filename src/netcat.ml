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

let run zonefiles log_level addressStrings data_subdomain port tcp udp
    enable_server nameserver =
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
        ~mono_clock:env#mono_clock ~tcp ~udp data_subdomain server_state log
        addresses
    in
    Eio.Flow.copy server server
  else
    let client =
      Transport.dns_client ~sw ~net:env#net ~clock:env#clock
        ~random:env#secure_random nameserver data_subdomain "example.org" port
        log
    in
    Eio.Fiber.both
      (fun () -> Eio.Flow.copy env#stdin client)
      (fun () -> Eio.Flow.copy client env#stdout)

let () =
  let cmd =
    let netcat_logging =
      Cmdliner.Arg.(
        value & opt int 0
        & info [ "l"; "log-level" ] ~docv:"LOG_LEVEL" ~doc:"Log level.")
    in
    let data_subdomain =
      Cmdliner.Arg.(
        value & opt string "rpc"
        & info [ "d"; "data-subdomain" ] ~docv:"DATA_SUBDOMAIN"
            ~doc:"Data subdomain.")
    in
    let server =
      Cmdliner.Arg.(
        value & opt bool true
        & info [ "s"; "server" ] ~docv:"SERVER" ~doc:"Server.")
    in
    let nameserver =
      Cmdliner.Arg.(
        value & opt string "127.0.0.1"
        & info [ "n"; "nameserver" ] ~docv:"NAMESERVER" ~doc:"Nameserver.")
    in
    let dns_t =
      Cmdliner.Term.(
        let open Server_args in
        const run $ zonefiles $ netcat_logging $ addresses $ data_subdomain
        $ port $ tcp $ udp $ server $ nameserver)
    in
    let info = Cmdliner.Cmd.info "dns" in
    Cmdliner.Cmd.v info dns_t
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
