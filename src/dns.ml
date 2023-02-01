
let handle_client sock _stdout =
  while true do
    let b = Cstruct.create 512 in
    let _senderSock, size = Eio.Net.recv sock b in
    Eio.traceln "Client: received %S" (Cstruct.to_string b ~len:size);
  done

let main ~net ~stdout =
  Eio.Switch.run @@ fun sw ->
  let get_sock addr = Eio.Net.datagram_socket ~sw net (`Udp (addr, 53)) in
  Eio.Fiber.both
    (fun () -> handle_client (get_sock Eio.Net.Ipaddr.V6.loopback) stdout)
    (fun () -> handle_client (get_sock Eio.Net.Ipaddr.V4.loopback) stdout)

let () = Eio_main.run @@ fun env ->
  main ~net:(Eio.Stdenv.net env) ~stdout:(Eio.Stdenv.stdout env)
