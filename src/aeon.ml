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

let run zonefiles log_level addressStrings port tcp udp =
  Eio_main.run @@ fun env ->
  let log = get_log log_level in
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
  Server.start ~net:env#net ~clock:env#clock ~mono_clock:env#mono_clock ~tcp
    ~udp server_state log addresses

let () =
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  let cmd =
    let dns_t =
      Cmdliner.Term.(
        let open Server_args in
        const run $ zonefiles $ logging $ addresses $ port $ tcp $ udp)
    in
    let info = Cmdliner.Cmd.info "dns" in
    Cmdliner.Cmd.v info dns_t
  in
  exit (Cmdliner.Cmd.eval cmd)
