let run log_level address_strings port connectPort proto domain subdomain
    nameserver timeout =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let log = Dns_log.get log_level Format.std_formatter in
  let addresses = Server_args.parse_addresses port address_strings in

  let client =
    (* todo use open resolver... *)
    Transport.Datagram_client.run ~sw env ~nameserver ~subdomain
      ~authorative:domain connectPort log timeout
  in

  let handle_dns _proto (addr : Eio.Net.Sockaddr.t) buf =
    client.send (Cstruct.of_string buf);
    (* todo out of order delivery? *)
    (* https://github.com/mirage/ocaml-dns/issues/345 *)
    let addr, recv =
      let buf = Cstruct.create 4096 in
      let got = client.recv buf in
      let trimmedBuf = Cstruct.sub buf 0 got in
      (addr, Cstruct.to_string trimmedBuf)
    in
    [ recv ]
  in
  Dns_server_eio.with_handler env proto handle_dns
    (Dns_log.get Dns_log.Level1 Format.std_formatter)
    addresses

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
    let connectPort =
      let doc =
        "The port to connect to the nameserver with. By default 53 is used. \
         See the BINDING section."
      in
      Arg.(
        value & opt int 53
        & info [ ""; "connect-port" ] ~docv:"CONNECT_PORT" ~doc)
    in
    let timeout =
      let doc = "Seconds to wait in between sending DNS queries." in
      Arg.(value & opt float 1. & info [ "t"; "timeout" ] ~docv:"TIMEOUT" ~doc)
    in
    let term =
      Term.(
        const run $ log_level Dns_log.Level0 $ addresses $ port $ connectPort
        $ proto $ domain $ subdomain $ nameserver $ timeout)
    in
    let doc = "DNS over DNS Obliviously (DoDO) Resolver" in
    let info = Cmd.info "dodo_resolver" ~man ~doc in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
