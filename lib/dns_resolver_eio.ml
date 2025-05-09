type dns_handler =
  Dns.proto ->
  Eio.Net.Sockaddr.t ->
  string ->
  (* answers *)
  (Dns.proto * Ipaddr.t * int * string) list (* queries *)
  * (Dns.proto * Ipaddr.t * string) list

let resolver_handle_dns env resolver_state : dns_handler =
 fun proto (addr : Eio.Net.Sockaddr.t) buf ->
  let new_resolver_state, answers, queries =
    let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
    and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock
    and ipaddr, port =
      match addr with
      | `Udp (ip, p) | `Tcp (ip, p) -> (
          let ip = Ipaddr.of_octets_exn (ip :> string) in
          (* convert IPV6-mapped arrs to IPv4 in order to avoid an unsolicited reply error *)
          (* another option would be to list listen on ipv4 -- but getting a `send_msg` error doing that *)
          match ip with
          | Ipaddr.V6 i -> (
              match Ipaddr.v4_of_v6 i with
              | Some i -> (Ipaddr.V4 i, p)
              | None -> (ip, p))
          | _ -> (ip, p))
      | `Unix _ -> failwith "Unix sockets not supported"
    in
    Dns_resolver.handle_buf !resolver_state now ts true proto ipaddr port buf
  in
  (* TODO is this thread safe? *)
  resolver_state := new_resolver_state;
  (answers, queries)

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
        let answers, queries = handle_dns `Udp addr recv in
        (* TODO do we need a mutex over sending? *)
        List.iter
          (fun (_proto, ip, p, b) ->
            (* TODO handle proto *)
            let addr = `Udp (Ipaddr.to_octets ip |> Eio.Net.Ipaddr.of_raw, p) in
            log Dns_log.Tx addr b;
            Eio.Net.send sock ~dst:addr [ Cstruct.of_string b ])
          answers;
        List.iter
          (fun (_proto, ip, b) ->
            (* TODO handle proto *)
            let addr =
              `Udp (Ipaddr.to_octets ip |> Eio.Net.Ipaddr.of_raw, 53)
            in
            log Dns_log.Tx addr b;
            Eio.Net.send sock ~dst:addr [ Cstruct.of_string b ])
          queries)
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
          let answers, queries = handle_dns `Tcp addr recv in
          (* TODO do we need a mutex over sending? *)
          List.iter
            (fun (_proto, ip, p, b) ->
              (* TODO handle proto *)
              (* TODO send to different addrs *)
              let _addr =
                `Udp (Ipaddr.to_octets ip |> Eio.Net.Ipaddr.of_raw, p)
              in
              log Dns_log.Tx addr b;
              (* add prefix, described in rfc1035 section 4.2.2 *)
              let prefix = Cstruct.create 2 in
              Cstruct.BE.set_uint16 prefix 0 (String.length b);
              Eio.Flow.write sock [ prefix; Cstruct.of_string b ])
            answers;
          List.iter
            (fun (_proto, ip, b) ->
              (* TODO handle proto *)
              log Dns_log.Tx addr b;
              (* TODO send to different addrs *)
              let _addr =
                `Udp (Ipaddr.to_octets ip |> Eio.Net.Ipaddr.of_raw, 53)
              in
              let prefix = Cstruct.create 2 in
              Cstruct.BE.set_uint16 prefix 0 (String.length b);
              Eio.Flow.write sock [ prefix; Cstruct.of_string b ])
            queries)
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

let resolver env proto resolver_state log addresses =
  let handle_dns = resolver_handle_dns env resolver_state in
  Listen.on_addrs ~net:env#net ~proto
    (udp_listen log handle_dns)
    (tcp_listen log handle_dns)
    addresses
