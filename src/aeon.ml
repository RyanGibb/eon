
let run zonefiles log_level data_subdomain = Eio_main.run @@ fun env ->
  let log = (match log_level with
    | 0 -> Dns_log.log_level_0
    | 1 -> Dns_log.log_level_1
    | 2 -> Dns_log.log_level_2
    | 3 -> Dns_log.log_level_3
    | _ -> if log_level < 0 then Dns_log.log_level_0 else Dns_log.log_level_2
  ) Format.std_formatter
  in
  let trie, keys = Zonefile.parse_zonefiles ~fs:(Eio.Stdenv.fs env) zonefiles in
  (* TODO modify ocaml-dns not to require this? *)
  (* We listen on in6addr_any to bind to all interfaces. If we also listen on
      INADDR_ANY, this collides with EADDRINUSE. However we can recieve IPv4 traffic
      too via IPv4-mapped IPv6 addresses [0]. It might be useful to look at using
      happy-eyeballs to choose between IPv4 and IPv6, however this may have
      peformance implications [2]. Better might be to explicitly listen per
      interface on IPv4 and/or Ipv6, which would allow the user granular control.
      BSD's also disable IPv4-mapped IPv6 address be default, so this would enable
      better portability.
      [0] https://www.rfc-editor.org/rfc/rfc3493#section-3.7
      [1] https://labs.apnic.net/presentations/store/2015-10-04-dns-dual-stack.pdf *)
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact (Eio.Stdenv.secure_random env) buf;
    buf
  in
  let server = ref @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign trie in
  let handle_dns = Server.dns_handler ~server ~clock:(Eio.Stdenv.clock env) ~mono_clock:(Eio.Stdenv.mono_clock env) ~data_subdomain in
  Eio.Fiber.both
  (fun () ->
    Eio.Switch.run @@ fun sw ->
    let sockUDP =
      try
        (* TODO make port configurable *)
        Eio.Net.datagram_socket ~sw (Eio.Stdenv.net env) (`Udp (Eio.Net.Ipaddr.V6.any, 53))
      with
      (* TODO proper error handling *)
      | Unix.Unix_error (Unix.EADDRINUSE, "bind", _) -> Eio.traceln "error"; failwith "whoops"
    in
    Server.udp_listen log handle_dns sockUDP)
  (fun () ->
    Eio.Switch.run @@ fun sw ->
    let sockTCP =
      try
        Eio.Net.listen ~sw ~backlog:4096 (Eio.Stdenv.net env) (`Tcp (Eio.Net.Ipaddr.V6.any, 53))
      with
      | Unix.Unix_error (Unix.EADDRINUSE, "bind", _) -> Eio.traceln "error"; failwith "oops"
    in
    let connection_handler = Server.tcp_handle log handle_dns in
    Server.tcp_listen sockTCP connection_handler);;

let cmd =
  (* TODO add port argument *)
  let zonefiles =
    Cmdliner.Arg.(value & opt_all string [] & info ["z"; "zonefile"] ~docv:"ZONEFILE_PATHS" ~doc:"Zonefile path.")
  in
  (* TODO add descriptions *)
  let logging =
    Cmdliner.Arg.(value & opt int 1 & info ["l"; "log-level"] ~docv:"LOG_LEVEL" ~doc:"Log level.")
  in
  let data_subdomain =
    Cmdliner.Arg.(value & opt string "rpc" & info ["d"; "data-subdomain"] ~docv:"DATA_SUBDOMAIN" ~doc:"Data subdoomain.")
  in
  let dns_t = Cmdliner.Term.(const run $ zonefiles $ logging $ data_subdomain) in
  let info = Cmdliner.Cmd.info "dns" in
  Cmdliner.Cmd.v info dns_t

let () =
  (* TODO make this configurable *)
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Error);
  exit (Cmdliner.Cmd.eval cmd)
