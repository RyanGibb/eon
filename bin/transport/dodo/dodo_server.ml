let run zonefiles log_level address_strings subdomain authorative port proto =
  Eio_posix.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let log = Dns_log.get log_level Format.std_formatter in
  let addresses = Server_args.parse_addresses port address_strings in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact env#secure_random buf;
    Cstruct.to_string buf
  in
  let server =
    let server_state =
      let trie', keys, parsedAuthorative =
        Zonefile.parse_zonefiles ~fs:env#fs zonefiles
      in
      let trie =
        match List.find_opt (fun a -> a == authorative) parsedAuthorative with
        | Some _ -> trie'
        | None ->
            Dns_trie.insert Domain_name.root Dns.Rr_map.Soa
              (Dns.Soa.create authorative)
              trie'
      in
      ref
      @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
           ~tsig_sign:Dns_tsig.sign trie
    in
    let authorative = Domain_name.to_string authorative in
    Transport.Datagram_server.run ~sw env proto ~subdomain ~authorative
      server_state log addresses
  in
  let resolver_state =
    let server_state =
      Dns_server.Primary.create ~rng ~tsig_verify:Dns_tsig.verify
        ~tsig_sign:Dns_tsig.sign Dns_trie.empty
    in
    let now = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
    ref
    @@ Dns_resolver.create ~cache_size:29 ~dnssec:false ~ip_protocol:`Ipv4_only
         now rng server_state
  in
  Eio.Fiber.fork ~sw (fun () ->
      Dns_resolver_eio.resolver env proto resolver_state
        (Dns_log.level_1 Format.std_formatter)
        [ (Eio.Net.Ipaddr.V4.any, 5056) ]);

  let clientSock =
    Eio.Net.datagram_socket ~sw env#net
      (`Udp (Eio.Net.Ipaddr.V4.loopback, 5057))
  in
  Eio.Fiber.both
    (fun () ->
      let buf = Cstruct.create 4096 in
      while true do
        let recv =
          let got = server.recv buf in
          let trimmedBuf = Cstruct.sub buf 0 got in
          Cstruct.to_string trimmedBuf
        in
        Dns_log.level_1 Format.std_formatter Dns_log.Rx (`Unix "tunneled") recv;
        Eio.Net.send clientSock
          ~dst:(`Udp (Eio.Net.Ipaddr.V4.loopback, 5056))
          [ buf ]
      done)
    (fun () ->
      let buf = Cstruct.create 4096 in
      while true do
        let addr, got = Eio.Net.recv clientSock buf in
        let trimmedBuf = Cstruct.sub buf 0 got in
        let recv = Cstruct.to_string trimmedBuf in
        Dns_log.level_1 Format.std_formatter Dns_log.Tx (`Unix "tunneled") recv;
        server.send trimmedBuf
      done)

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
    let authorative =
      let doc =
        "Domain for which the server is authorative and that we will use to \
         tunnel data at the SUBDOMAIN."
      in
      Arg.(
        required
        & opt (some (conv (Domain_name.of_string, Domain_name.pp))) None
        & info [ "a"; "authorative" ] ~docv:"AUTHORATIVE" ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.Level1 $ addresses $ subdomain
        $ authorative $ port $ proto)
    in
    let doc = "DNS over DNS Obliviously (DoDO) Server" in
    let info = Cmd.info "dodo_server" ~man ~doc in
    Cmd.v info term
  in
  exit (Cmdliner.Cmd.eval cmd)
