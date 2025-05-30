type dns_handler = Dns.proto -> Eio.Net.Sockaddr.t -> string -> string list

let primary_handle_dns env server_state packet_callback : dns_handler =
 fun proto (addr : Eio.Net.Sockaddr.t) buf ->
  (* TODO handle notify, n, and key *)
  let new_server_state, answers, _notify, _n, _key =
    let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
    and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock
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
    let addr, recv =
      (* Create a new buffer for every recv.
         Support queries of up to 4kB.
         The 512B limit described in rfc1035 section 2.3.4 is outdated) *)
      let buf = Cstruct.create 4096 in
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
    (* fork a thread to process packet and reply, so we can continue to listen for packets *)
    Eio.Fiber.fork ~sw (fun () ->
        let answers = handle_dns `Udp addr recv in
        (* TODO do we need a mutex over sending? *)
        List.iter
          (fun b ->
            log Dns_log.Tx addr b;
            Eio.Net.send sock ~dst:addr [ Cstruct.of_string b ])
          answers)
  done

let tcp_handle log handle_dns : _ Eio.Net.connection_handler =
 fun sock addr ->
  Eio.Switch.run @@ fun sw ->
  (* Persist connection until EOF, rfc7766 section 6.2.1 *)
  try
    while true do
      let addr, recv =
        (* Messages sent over TCP have a 2 byte prefix giving the message length, rfc1035 section 4.2.2 *)
        let prefix = Cstruct.create 2 in
        Eio.Flow.read_exact sock prefix;
        let len = Cstruct.BE.get_uint16 prefix 0 in
        let buf = Cstruct.create len in
        Eio.Flow.read_exact sock buf;
        (addr, Cstruct.to_string buf)
      in
      (* convert Eio.Net.Sockaddr.stream to Eio.Net.Sockaddr.t *)
      let addr = match addr with `Tcp a -> `Tcp a | `Unix u -> `Unix u in
      log Dns_log.Rx addr recv;
      (* fork a thread to process packet and reply, so we can continue to listen for packets *)
      Eio.Fiber.fork ~sw (fun () ->
          let answers = handle_dns `Tcp addr recv in
          List.iter
            (fun b ->
              log Dns_log.Tx addr b;
              (* add prefix, described in rfc1035 section 4.2.2 *)
              let prefix = Cstruct.create 2 in
              Cstruct.BE.set_uint16 prefix 0 (String.length b);
              Eio.Flow.write sock [ prefix; Cstruct.of_string b ])
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

let with_handler env proto handle_dns log addresses =
  Listen.on_addrs ~net:env#net ~proto
    (udp_listen log handle_dns)
    (tcp_listen log handle_dns)
    addresses

let primary env proto ?(packet_callback = fun _q -> None) server_state log
    addresses =
  let handle_dns = primary_handle_dns env server_state packet_callback in
  Listen.on_addrs ~net:env#net ~proto
    (udp_listen log handle_dns)
    (tcp_listen log handle_dns)
    addresses
