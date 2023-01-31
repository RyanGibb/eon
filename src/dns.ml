
let handle_client sock _stdout =
  let b = Cstruct.create 100 in
  let _sock2, _i = sock#recv b in
  Eio.traceln "Client: received %S" (Cstruct.to_string b)

let () =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let bindaddr = `Udp (Eio.Net.Ipaddr.V4.loopback, 53) in
  let sock = Eio.Net.datagram_socket ~sw (Eio.Stdenv.net env) bindaddr in
  handle_client sock (Eio.Stdenv.stdout env);;
