let run log_level domain subdomain port nameserver netmask tunnel_ip =
  let log = (Dns_log.get_log log_level) Format.std_formatter in
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let client =
    Transport.dns_client ~sw ~net:env#net ~clock:env#clock
      ~random:env#secure_random nameserver subdomain domain port log
  in
  let tun_fd, tun_name = Tuntap.opentun ~devname:"tun-dns" () in
  let tun = Eio_unix.FD.as_socket ~sw ~close_unix:false tun_fd in
  let process_incoming () =
    let buf = Cstruct.create 4096 in
    try
      while true do
        let got = Eio.Flow.single_read client buf in
        Eio.traceln "inc %d" got;
        tun#write [ Cstruct.sub buf 0 got ]
      done
    with End_of_file -> ()
  in
  let process_outgoing () =
    let buf = Cstruct.create 4096 in
    try
      while true do
        let got = Eio.Flow.single_read tun buf in
        Eio.traceln "out %d" got;
        client#write [ Cstruct.sub buf 0 got ]
      done
    with End_of_file -> ()
  in
  Tuntap.set_ipv4 tun_name
    ~netmask:(Ipaddr.V4.Prefix.of_string_exn netmask)
    (Ipaddr.V4.of_string_exn tunnel_ip);
  Tuntap.set_up_and_running tun_name;
  Eio.Fiber.both (fun () -> process_outgoing ()) (fun () -> process_incoming ())

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
    let netmask =
      Arg.(
        value & opt string "10.0.0.0/24"
        & info [ "m"; "netmask" ] ~docv:"NETMASK")
    in
    let tunnel_ip =
      Arg.(
        value & opt string "10.0.0.2"
        & info [ "i"; "tunnel_ip" ] ~docv:"TUNNEL_IP")
    in
    let term =
      Term.(
        const run $ logging_default 0 $ domain $ subdomain $ port $ nameserver
        $ netmask $ tunnel_ip)
    in
    let doc = "An authorative nameserver using OCaml 5 Algebraic Effects" in
    let info = Cmd.info "netcat" ~man ~doc in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
