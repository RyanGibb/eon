
let handle_client flow _addr stdout =
  Eio.Flow.copy_string "Hello from server" flow;
  Eio.Flow.copy_string "Hello from server" stdout

let () = Eio_main.run @@ fun env ->
  let flow = Eio_mock.Flow.make "flow" in
  let addr = `Tcp (Eio.Net.Ipaddr.V4.loopback, 37568) in
  handle_client flow addr (Eio.Stdenv.stdout env);;
