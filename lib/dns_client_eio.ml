type 'a dns_handler = Dns.proto -> Eio.Net.Sockaddr.t -> string -> 'a -> 'a

let udp_listen log sock handle_dns state =
  let buf = Cstruct.create 4096 in
  let rec loop state =
    let addr, recv =
      let addr, size = Eio.Net.recv sock buf in
      let trimmedBuf = Cstruct.sub buf 0 size in
      (addr, Cstruct.to_string trimmedBuf)
    in
    (* convert Eio.Net.Sockaddr.datagram to Eio.Net.Sockaddr.t *)
    let addr =
      match addr with
      | `Udp a -> `Udp a
      | `Unix _ -> failwith "unix domain sockets unsupported"
    in
    log Dns_log.Rx addr recv;
    let state = handle_dns `Udp addr recv state in
    loop state
  in
  loop state

let create_query identifier record_type name =
  let question = Dns.Packet.Question.create name record_type
  and header =
    let flags = Dns.Packet.Flags.singleton `Recursion_desired in
    (identifier, flags)
  in
  let query = Dns.Packet.create header question `Query in
  let cs, _ = Dns.Packet.encode `Udp query in
  cs

let send_query log identifier record_type name sock addr =
  let query = create_query identifier record_type name in
  (* convert Eio.Net.Sockaddr.datagram to Eio.Net.Sockaddr.t *)
  let addr =
    match addr with
    | `Udp a -> `Udp a
    | `Unix _ -> failwith "unix domain sockets unsupported"
  in
  log Dns_log.Tx addr query;
  Eio.Net.send sock ~dst:addr [ Cstruct.of_string query ]

let listen sock log (handle_dns : _ dns_handler) state =
  udp_listen log sock handle_dns state
