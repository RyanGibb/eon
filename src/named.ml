let run zonefiles log_level addressStrings port no_tcp no_udp =
  if no_tcp && no_udp then (
    Format.fprintf Format.err_formatter "Either UDP or TCP should be enabled\n";
    Format.pp_print_flush Format.err_formatter ();
    exit 1);
  let tcp = not no_tcp and udp = not no_udp in
  Eio_main.run @@ fun env ->
  let log = (Dns_log.get_log log_level) Format.std_formatter in
  let addresses = Server_args.parse_addresses port addressStrings in
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
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let term =
      Term.(
        const run $ zonefiles $ logging $ addresses $ port $ no_tcp $ no_udp)
    in
    let info = Cmd.info "aeon" ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
