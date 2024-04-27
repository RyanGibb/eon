let run log_level domain subdomain port nameserver =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let log = Dns_log.get log_level Format.std_formatter in
  let client =
    Transport.dns_client_datagram ~sw ~net:env#net ~clock:env#clock ~random:env#secure_random nameserver subdomain
      domain port log
  in
  Eio.Fiber.both
    (fun () ->
      let buf = Cstruct.create 1000 in
      while true do
        let got = Eio.Flow.single_read env#stdin buf in
        client.send (Cstruct.sub buf 0 got)
      done)
    (fun () ->
      let buf = Cstruct.create 1000 in
      while true do
        let got = client.recv buf in
        Eio.Flow.write env#stdout [ Cstruct.sub buf 0 got ]
      done)

(* Eio.Fiber.both (fun () -> Eio.Flow.copy env#stdin client) (fun () -> Eio.Flow.copy client env#stdout) *)

let () =
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let subdomain =
      let doc =
        "Sudomain to use custom processing on. This will be combined with the root DOMAIN to form \
         <SUBDOMAIN>.<DOMAIN>, e.g. rpc.example.org. Data will be encoded as a base 64 string as a sudomain of this \
         domain giving <DATA>.<SUBDOMAIN>.<DOMAIN>, e.g. aGVsbG8K.rpc.example.org."
      in
      Arg.(value & opt string "rpc" & info [ "sd"; "subdomain" ] ~docv:"SUBDOMAIN" ~doc)
    in
    let domain =
      let doc = "Domain that the NAMESERVER is authorative for." in
      Arg.(value & opt string "example.org" & info [ "d"; "domain" ] ~docv:"DOMAIN" ~doc)
    in
    let nameserver =
      let doc =
        "The address of the nameserver to query. The first result returned by getaddrinfo will be used. If this may \
         return multiple values, e.g. an IPv4 and IPv6 address for a host, and a specific one is desired it should be \
         specified."
      in
      Arg.(value & opt string "127.0.0.1" & info [ "n"; "nameserver" ] ~docv:"NAMESERVER" ~doc)
    in
    let term = Term.(const run $ log_level Dns_log.Level0 $ domain $ subdomain $ port $ nameserver) in
    let doc = "An authorative nameserver using OCaml 5 effects-based IO" in
    let info = Cmd.info "netcat" ~man ~doc in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
