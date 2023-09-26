type dns_handler = Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit

let udp_listen log sock handle_dns =
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    (* convert Eio.Net.Sockaddr.datagram to Eio.Net.Sockaddr.t *)
    let addr = match addr with `Udp a -> `Udp a in
    log Dns_log.Rx addr trimmedBuf;
    handle_dns `Udp addr trimmedBuf
  done

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
  let addr = match addr with `Udp a -> `Udp a in
  log Dns_log.Tx addr query;
  Eio.Net.send sock addr query

let listen sock log (handle_dns : dns_handler) = udp_listen log sock handle_dns
