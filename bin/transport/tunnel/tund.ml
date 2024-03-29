let run zonefiles log_level addressStrings domain subdomain port proto
    netmask tunnel_ip =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let log = log_level Format.std_formatter in
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
      ~mono_clock:env#mono_clock ~proto subdomain domain server_state log
      addresses
  in
  let tun_fd, tun_name = Tuntap.opentun ~devname:"tun-dnsd" () in
  let tun = Eio_unix.Net.import_socket_stream ~sw ~close_unix:false tun_fd in
  Tuntap.set_ipv4 tun_name
    ~netmask:(Ipaddr.V4.Prefix.of_string_exn netmask)
    (Ipaddr.V4.of_string_exn tunnel_ip);
  Eio.Fiber.both
    (fun () ->
      let buf = Cstruct.create (Tuntap.get_mtu tun_name) in
      while true do
        let got = server#recv buf in
        Eio.Flow.write tun [ Cstruct.sub buf 0 got ]
      done)
    (fun () ->
      let buf = Cstruct.create (Tuntap.get_mtu tun_name) in
      while true do
        let got = Eio.Flow.single_read tun buf in
        server#send (Cstruct.sub buf 0 got)
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
    let netmask =
      Arg.(
        value & opt string "10.0.0.0/24"
        & info [ "m"; "netmask" ] ~docv:"NETMASK")
    in
    let tunnel_ip =
      Arg.(
        value & opt string "10.0.0.1"
        & info [ "i"; "tunnel_ip" ] ~docv:"TUNNEL_IP")
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.level_1 $ addresses $ domain $ subdomain $ port
        $ proto $ netmask $ tunnel_ip)
    in
    let doc = "An authorative nameserver using OCaml 5 effects-based IO" in
    let info = Cmd.info "tund" ~man ~doc in
    Cmd.v info term
  in
  exit (Cmdliner.Cmd.eval cmd)
