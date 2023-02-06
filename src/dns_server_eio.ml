
let listen sock _server =
  let buf = Cstruct.create 512 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let buf_trim = Cstruct.sub buf 0 size in
    Eio.traceln "received:"; Cstruct.hexdump buf_trim;
    match Dns.Packet.decode buf_trim with
    | Error e -> Dns.Packet.pp_err Fmt.stdout e
    | Ok query ->
      Dns.Packet.pp Fmt.stdout query; Fmt.flush Fmt.stdout ();
      Eio.Net.send sock addr buf_trim
  done

let main ~net ~random =
  Eio.Switch.run @@ fun sw ->
  let get_sock addr = Eio.Net.datagram_socket ~sw net (`Udp (addr, 53)) in
  (* TODO load from zonefile *)
  (* let zones, trie, keys = Dns_zone.decode_zones_keys bindings in *)
  let trie = Dns_trie.empty in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact random buf;
    buf
  in
  let server = ref @@ Dns_server.Primary.create ~rng trie in
  Eio.Fiber.both
    (fun () -> listen (get_sock Eio.Net.Ipaddr.V6.loopback) server)
    (fun () -> listen (get_sock Eio.Net.Ipaddr.V4.loopback) server)

let () = Eio_main.run @@ fun env ->
  main ~net:(Eio.Stdenv.net env) ~random:(Eio.Stdenv.secure_random env)
