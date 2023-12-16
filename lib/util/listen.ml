(* bind to sockets with callback/conection handler *)

let on_addrs ~net ~proto udp_listen tcp_listen addrs =
  let on_addr addr =
    let try_bind bind addr =
      try bind addr
      with Unix.Unix_error (error, "bind", _) ->
        Format.fprintf Format.err_formatter "Error binding to %a %s\n"
          Eio.Net.Sockaddr.pp addr (Unix.error_message error);
        Format.pp_print_flush Format.err_formatter ();
        exit 2
    in
    List.map (fun proto ->
      match proto with
      | `Udp ->
        (fun () ->
          Eio.Switch.run @@ fun sw ->
          let sockUDP =
            try_bind
              (Eio.Net.datagram_socket ~sw ~reuse_addr:true net)
              (`Udp addr)
          in
          udp_listen sockUDP)
      | `Tcp ->
        (fun () ->
          Eio.Switch.run @@ fun sw ->
          let sockTCP =
            try_bind
              (Eio.Net.listen ~sw ~reuse_addr:true ~backlog:4096 net)
              (`Tcp addr)
          in
          tcp_listen sockTCP)
    ) proto
  in Eio.Fiber.all (List.flatten (List.map on_addr addrs))
