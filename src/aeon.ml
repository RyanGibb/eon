
let parse_zonefiles ~fs zonefiles =
  let trie, keys = List.fold_left (fun (trie, keys) zonefile ->
    let ( / ) = Eio.Path.( / ) in
    match
      let data = Eio.Path.load @@ fs / zonefile in
      Dns_zone.parse data
    with
    | Error `Msg msg ->
      Format.fprintf Format.std_formatter "ignoring zonefile %s: %s" zonefile msg;
      trie, keys
    | Ok rrs ->
      let keys' =
        try
          let keydata = Eio.Path.load @@ fs / (zonefile ^ "._keys") in
          match Dns_zone.parse keydata with
          | Error `Msg msg ->
            Format.fprintf Format.std_formatter "ignoring zonefile %s: %s" zonefile msg;
            keys
          | Ok rrs ->
            let keys' = Domain_name.Map.fold (fun n data acc ->
              match Dns.Rr_map.(find Dnskey data) with
              | None ->
                Format.fprintf Format.std_formatter "no dnskey found %a" Domain_name.pp n;
                acc
              | Some (_, keys) ->
                match Dns.Rr_map.Dnskey_set.elements keys with
                | [ x ] -> Domain_name.Map.add n x acc
                | xs ->
                  Format.fprintf Format.std_formatter
                  "ignoring %d dnskeys for %a (only one supported)"
                    (List.length xs) Domain_name.pp n;
                  acc)
              rrs Domain_name.Map.empty
            in
            let f key a _b =
              Format.fprintf Format.std_formatter "encountered deplicate key %a"
                Domain_name.pp key;
              Some a
            in
            Domain_name.Map.union f keys keys'
        with
          Eio.Io _ -> keys
      in
      let trie' = Dns_trie.insert_map rrs trie in
      trie', keys')
    (Dns_trie.empty, Domain_name.Map.empty)
    zonefiles in
  let keys = Domain_name.Map.bindings keys in
  trie, keys

let convert_eio_to_ipaddr (addr : Eio.Net.Sockaddr.datagram) =
  match addr with
  | `Udp (ip, p) ->
    let src = (ip :> string) in
    let src = Eio.Net.Ipaddr.fold
      ~v4:(fun _v4 -> Ipaddr.V4 (Result.get_ok @@ Ipaddr.V4.of_octets src))
      ~v6:(fun _v6 -> Ipaddr.V6 (Result.get_ok @@ Ipaddr.V6.of_octets src))
      ip
    in
    src, p

let listen ~clock ~mono_clock ~log sock server =
  let buf = Cstruct.create 512 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    log `Rx addr buf;
    (* todo handle these *)
    let new_server, answers, _notify, _n, _key =
      let now = Ptime.of_float_s @@ Eio.Time.now clock |> Option.get in
      let ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now mono_clock in
      let src, port = convert_eio_to_ipaddr addr in
      Dns_server.Primary.handle_buf !server now ts `Udp src port trimmedBuf
    in
    server := new_server;
    List.iter (fun b -> log `Tx addr b; Eio.Net.send sock addr b) answers
  done

let main ~net ~random ~clock ~mono_clock ~fs ~zonefiles ~log =
  Eio.Switch.run @@ fun sw ->
  let trie, keys = parse_zonefiles ~fs zonefiles in
  Format.print_space ();
  Format.print_flush ();
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact random buf;
    buf
  in
  let server = ref @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign trie in
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
  let sock = Eio.Net.datagram_socket ~sw net (`Udp (Eio.Net.Ipaddr.V6.any, 53)) in
  listen ~clock ~mono_clock ~log sock server

let log_level_0 _direction _addr _buf = ()

let log_helper direction addr buf log_packet =
  let log_transmssion direction addr =
    (match direction with
    | `Rx -> Format.fprintf Format.std_formatter "<-"
    | `Tx -> Format.fprintf Format.std_formatter "->");
    Format.print_space ();
    Eio.Net.Sockaddr.pp Format.std_formatter addr;
    Format.print_space ()
  in
  log_transmssion direction addr;
  match Dns.Packet.decode buf with
  | Error e ->
    Format.fprintf Format.std_formatter "error decoding:";
    Format.print_space ();
    Dns.Packet.pp_err Format.std_formatter e
  | Ok packet -> log_packet packet;
  Format.print_space (); Format.print_space ();
  Format.print_flush ()

let log_level_1 direction addr buf =
  let log_packet (packet : Dns.Packet.t) =
    Format.fprintf Format.std_formatter "question %a@ data %a@"
      Dns.Packet.Question.pp packet.question
      Dns.Packet.pp_data packet.data
  in
  log_helper direction addr buf log_packet

let log_level_2 direction addr buf =
  let log_packet = Dns.Packet.pp Format.std_formatter in
  log_helper direction addr buf log_packet
  
let run zonefiles log_level = Eio_main.run @@ fun env ->
  let log = match log_level with
    | 0 -> log_level_0
    | 1 -> log_level_1
    | 2 -> log_level_2
    | _ -> if log_level < 0 then log_level_0 else log_level_2
  in
  main
    ~net:(Eio.Stdenv.net env)
    ~random:(Eio.Stdenv.secure_random env)
    ~clock:(Eio.Stdenv.clock env)
    ~mono_clock:(Eio.Stdenv.mono_clock env)
    ~fs:(Eio.Stdenv.fs env)
    ~zonefiles
    ~log

let cmd =
  let zonefiles =
    let doc = "Zonefile path." in
    Cmdliner.Arg.(value & opt_all string [] & info ["z"; "zonefile"] ~docv:"ZONEFILE_PATHS" ~doc) in
  let logging =
    let doc = "Log level." in
    Cmdliner.Arg.(value & opt int 1 & info ["l"; "log-level"] ~docv:"LOG_LEVEL" ~doc)
  in
  let dns_t = Cmdliner.Term.(const run $ zonefiles $ logging) in
  let info = Cmdliner.Cmd.info "dns" in
  Cmdliner.Cmd.v info dns_t

let () = exit (Cmdliner.Cmd.eval cmd)
