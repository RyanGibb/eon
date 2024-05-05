let run zonefiles log_level address_strings subdomain authorative port proto
    mode =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let log = Dns_log.get log_level Format.std_formatter in
  let addresses = Server_args.parse_addresses port address_strings in
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
    let rng ?_g length =
      let buf = Cstruct.create length in
      Eio.Flow.read_exact env#secure_random buf;
      buf
    in
    ref
    @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
         ~tsig_sign:Dns_tsig.sign trie
  in
  let authorative = Domain_name.to_string authorative in
  match mode with
  | `Datagram ->
      let server =
        (* TODO remember why datagram needs and authority, but not stream, and then remove the hardcoded value *)
        Transport.Datagram_server.run ~sw env proto ~subdomain ~authorative
          server_state log addresses
      in
      let buf = Cstruct.create 1000 in
      while true do
        let got = server.recv buf in
        server.send (Cstruct.sub buf 0 got)
      done
  | `Stream ->
      let server =
        Transport.Stream_server.run ~sw env proto ~subdomain ~authorative
          server_state log addresses
      in
      Eio.Flow.copy server server

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
    let mode =
      let doc = "The type of transport protocol to run over DNS." in
      let modes = [ ("datagram", `Datagram); ("stream", `Stream) ] in
      Arg.(
        value
        & opt (enum modes) `Datagram
        & info [ "m"; "mode" ] ~docv:"MODES" ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.Level1 $ addresses $ subdomain
        $ authorative $ port $ proto $ mode)
    in
    let doc = "An authorative nameserver using OCaml 5 effects-based IO" in
    let info = Cmd.info "netcatd" ~man ~doc in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
