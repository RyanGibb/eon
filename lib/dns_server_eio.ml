type dns_handler =
  Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list

let primary_handle_dns ~clock ~mono_clock server_state packet_callback :
    dns_handler =
 fun proto (addr : Eio.Net.Sockaddr.t) buf ->
  (* TODO handle notify, n, and key *)
  let new_server_state, answers, _notify, _n, _key =
    let now = Ptime.of_float_s @@ Eio.Time.now clock |> Option.get
    and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now mono_clock
    and ipaddr, port =
      match addr with
      | `Udp (ip, p) | `Tcp (ip, p) -> (Ipaddr.of_octets_exn (ip :> string), p)
      | `Unix _ -> failwith "Unix sockets not supported"
    in
    Dns_server.Primary.handle_buf !server_state now ts proto ipaddr port buf
      ~packet_callback
  in
  (* TODO is this thread safe? *)
  server_state := new_server_state;
  answers

let udp_listen log handle_dns sock =
  Eio.Switch.run @@ fun sw ->
  while true do
    (* Create a new buffer for every recv.
       Support queries of up to 4kB.
       The 512B limit described in rfc1035 section 2.3.4 is outdated) *)
    let buf = Cstruct.create 4096 in
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    (* convert Eio.Net.Sockaddr.datagram to Eio.Net.Sockaddr.t *)
    let addr = match addr with `Udp a -> `Udp a in
    log Dns_log.Rx addr trimmedBuf;
    (* fork a thread to process packet and reply, so we can continue to listen for packets *)
    Eio.Fiber.fork ~sw (fun () ->
        let answers = handle_dns `Udp addr trimmedBuf in
        (* TODO do we need a mutex over sending? *)
        List.iter
          (fun b ->
            log Dns_log.Tx addr b;
            Eio.Net.send sock addr b)
          answers)
  done

type connection_handler =
  Eio.Net.stream_socket -> Eio.Net.Sockaddr.stream -> unit

let tcp_handle log handle_dns : connection_handler =
 fun sock addr ->
  Eio.Switch.run @@ fun sw ->
  (* Persist connection until EOF, rfc7766 section 6.2.1 *)
  try
    while true do
      (* Messages sent over TCP have a 2 byte prefix giving the message length, rfc1035 section 4.2.2 *)
      let prefix = Cstruct.create 2 in
      Eio.Flow.read_exact sock prefix;
      let len = Cstruct.BE.get_uint16 prefix 0 in
      let buf = Cstruct.create len in
      Eio.Flow.read_exact sock buf;
      (* convert Eio.Net.Sockaddr.stream to Eio.Net.Sockaddr.t *)
      let addr = match addr with `Tcp a -> `Tcp a | `Unix u -> `Unix u in
      log Dns_log.Rx addr buf;
      (* fork a thread to process packet and reply, so we can continue to listen for packets *)
      Eio.Fiber.fork ~sw (fun () ->
          let answers = handle_dns `Tcp addr buf in
          List.iter
            (fun b ->
              log Dns_log.Tx addr b;
              (* add prefix, described in rfc1035 section 4.2.2 *)
              let prefix = Cstruct.create 2 in
              Cstruct.BE.set_uint16 prefix 0 b.len;
              Eio.Flow.write sock [ prefix; b ])
            answers)
    done
    (* ignore EOF *)
  with End_of_file -> ()

let tcp_listen log handle_dns sock =
  while true do
    let on_error err =
      Format.fprintf Format.err_formatter "Error handling connection: %a\n"
        Fmt.exn err;
      Format.pp_print_flush Format.err_formatter ()
    in
    Eio.Switch.run @@ fun sw ->
    Eio.Net.accept_fork ~sw sock ~on_error (tcp_handle log handle_dns)
  done

let with_handler ~net ~proto handle_dns log addresses =
  Listen.on_addrs ~net ~proto
    (udp_listen log handle_dns)
    (tcp_listen log handle_dns)
    addresses

let primary ~net ~clock ~mono_clock ~proto
    ?(packet_callback = fun _q -> None) server_state log addresses =
  let handle_dns =
    primary_handle_dns ~clock ~mono_clock server_state packet_callback
  in
  Listen.on_addrs ~net ~proto
    (udp_listen log handle_dns)
    (tcp_listen log handle_dns)
    addresses
