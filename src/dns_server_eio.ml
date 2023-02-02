
let handle_client sock _stdout =
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

let main ~net ~stdout =
  Eio.Switch.run @@ fun sw ->
  let get_sock addr = Eio.Net.datagram_socket ~sw net (`Udp (addr, 53)) in
  Eio.Fiber.both
    (fun () -> handle_client (get_sock Eio.Net.Ipaddr.V6.loopback) stdout)
    (fun () -> handle_client (get_sock Eio.Net.Ipaddr.V4.loopback) stdout)

let () = Eio_main.run @@ fun env ->
  main ~net:(Eio.Stdenv.net env) ~stdout:(Eio.Stdenv.stdout env)
