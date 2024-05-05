let get_packet_callback server_state =
  let packet_callback (p : Dns.Packet.t) : Dns.Packet.t option =
    let ( let* ) = Option.bind in
    let* question =
      match p.Dns.Packet.data with `Query -> Some p.question | _ -> None
    in

    let* flags, data, additional =
      match
        Dns_server.handle_question
          (Dns_server.Primary.server !server_state)
          question
      with
      | Error (_rcode, _data) -> None
      | Ok (flags, data, additional) -> Some (flags, `Answer data, additional)
    in

    let name, _qtype = question in

    (* custom processing ... *)
    let hostname = Domain_name.of_string_exn "" in

    (* TODO how to plumb host statues through here? *)
    let rr = Dns.Rr_map.singleton Dns.Rr_map.Cname (0l, hostname) in
    let answer = Domain_name.Map.singleton name rr in
    let authority = Dns.Name_rr_map.empty in
    let _reply = `Answer (answer, authority) in

    let packet =
      Dns.Packet.create ?additional (fst p.header, flags) p.question data
    in
    Some packet
  in
  packet_callback
