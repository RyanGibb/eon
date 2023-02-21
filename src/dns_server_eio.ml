
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
    let addr, _size = Eio.Net.recv sock buf in
    log `Rx addr buf;
    (* todo handle these *)
    let new_server, answers, _notify, _n, _key =
      let now = Ptime.of_float_s @@ Eio.Time.now clock |> Option.get in
      let ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now mono_clock in
      let src, port = convert_eio_to_ipaddr addr in
      Dns_server.Primary.handle_buf !server now ts `Udp src port buf
    in
    server := new_server;
    List.iter (fun b -> log `Tx addr b; Eio.Net.send sock addr b) answers
  done

let main ~net ~random ~clock ~mono_clock ~bindings ~log =
  Eio.Switch.run @@ fun sw ->
  let _zones, trie, keys = Dns_zone.decode_zones_keys bindings in
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
  let bindings =
    let map zonefile =
      let ( / ) = Eio.Path.( / ) in
      let path = (Eio.Stdenv.fs env) / zonefile in
      let name = Filename.basename zonefile in
      let zonefile_binding = name, Eio.Path.load path in
      try
        let path_keys = (Eio.Stdenv.fs env) / (zonefile ^ "._keys") in
        let name_keys = name ^ "._keys" in
        [ zonefile_binding; (name_keys, Eio.Path.load path_keys) ]
      with
        Eio.Io _ -> [ zonefile_binding ]
    in
    List.concat_map map zonefiles
  in
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
    ~bindings
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
