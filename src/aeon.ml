let run zonefiles log_level data_subdomain addresses port tcp udp =
  Eio_main.run @@ fun env ->
  (* command line parameter parsing *)
  let log =
    (match log_level with
    | 0 -> Dns_log.log_level_0
    | 1 -> Dns_log.log_level_1
    | 2 -> Dns_log.log_level_2
    | 3 -> Dns_log.log_level_3
    | _ -> if log_level < 0 then Dns_log.log_level_0 else Dns_log.log_level_2)
      Format.std_formatter
  in
  let addresses =
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
      addresses
  in

  (* setup server *)
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
  let server =
    ref
    @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
         ~tsig_sign:Dns_tsig.sign trie
  in
  let handle_dns =
    Server.dns_handler ~server ~clock:(Eio.Stdenv.clock env)
      ~mono_clock:(Eio.Stdenv.mono_clock env)
      ~callback:(Transport.callback ~data_subdomain)
  in

  (* bind to sockets with callback/conection handler *)
  let listen_on_address addr =
    let try_bind bind addr =
      try bind addr
      with Unix.Unix_error (error, "bind", _) ->
        Format.fprintf Format.err_formatter "Error binding to %a %s\n"
          Eio.Net.Sockaddr.pp addr (Unix.error_message error);
        exit 2
    in
    (if udp then
       [
         (fun () ->
           Eio.Switch.run @@ fun sw ->
           let sockUDP =
             try_bind (Eio.Net.datagram_socket ~sw env#net) (`Udp addr)
           in
           Server.udp_listen log handle_dns sockUDP);
       ]
     else [])
    @
    if tcp then
      [
        (fun () ->
          Eio.Switch.run @@ fun sw ->
          let sockTCP =
            try_bind (Eio.Net.listen ~sw ~backlog:4096 env#net) (`Tcp addr)
          in
          let connection_handler = Server.tcp_handle log handle_dns in
          Server.tcp_listen sockTCP connection_handler);
      ]
    else []
  in
  Eio.Fiber.all (List.flatten (List.map listen_on_address addresses))

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
      
      A can be specified, e.g. with `[::]:5053`, otherwise the default
      `port` is used.

      If IPv4-mapped IPv6 is not supported, e.g. on OpenBSD, the user will 
      need to specify an IPv4 address in order to server IPv4 traffic, e.g.
      `-a 127.0.0.1 -a '::'`.

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
      const run $ zonefiles $ logging $ data_subdomain $ addresses $ port $ tcp
      $ udp)
  in
  let info = Cmdliner.Cmd.info "dns" in
  Cmdliner.Cmd.v info dns_t

let () =
  (* TODO make this configurable *)
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Error);
  exit (Cmdliner.Cmd.eval cmd)
