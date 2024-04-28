let run ~sw env proto ~subdomain ~authorative server_state log addresses =
  let inc = Cstruct_stream.create () and out = Cstruct_stream.create () in

  (* TODO mutex *)
  let last_recv_seq_no = ref (-1)
  and last_sent_seq_no = ref 0
  and seq_no = ref 0 in

  let buf = ref Cstruct.empty in

  let packet_callback (p : Dns.Packet.t) : Dns.Packet.t option =
    let ( let* ) = Option.bind in
    let* name, qtype =
      match p.Dns.Packet.data with `Query -> Some p.question | _ -> None
    in
    let* recv_buf, root = Domain_name_data.decode subdomain name in

    let* () =
      if String.lowercase_ascii (Domain_name.to_string root) = authorative then
        Some ()
      else (
        Eio.traceln "Ignoring query to domain %a" Domain_name.pp root;
        None)
    in
    let domain = Domain_name.prepend_label_exn root subdomain in

    (* Only process CNAME queries *)
    let* _ =
      match qtype with
      | `K (Dns.Rr_map.K Dns.Rr_map.Cname) -> Some ()
      | `Axfr | `Ixfr ->
          Format.fprintf Format.err_formatter
            "Transport: unsupported operation zonetransfer\n";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `Any ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR ANY\n";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `K rr ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR %a\n"
            Dns.Rr_map.ppk rr;
          Format.pp_print_flush Format.err_formatter ();
          None
    in

    let packet = Unique_packet.decode recv_buf in

    let* reply =
      (* allow resetting stream *)
      (* TODO sessions *)
      (* TODO think about this a bit *)
      (* TODO this duplicates packets if multiple are sent before a reply is recieved *)
      if packet.seq_no == 0 && Cstruct.length packet.data == 0 then (
        last_sent_seq_no := 0;
        seq_no := 0);

      (* if this is a data carrying packet, reply with an ack *)
      if Cstruct.length packet.data > 0 then (
        (* if we haven't already recieved this sequence number *)
        (* TODO a rogue packet from a bad actor could break this stream, or a delayed retransmission from a resolver *)
        if packet.seq_no != !last_recv_seq_no then
          Cstruct_stream.add inc [ packet.data ];
        last_recv_seq_no := packet.seq_no;
        (* an ack is a packet carrying no data *)
        Some (Packet.encode packet.seq_no Cstruct.empty))
      else if
        (* If the last packet hasn't been recieved, retransmit.
           NB if there's no data, the sequence number is confirming the last recieved. *)
        packet.seq_no == !last_sent_seq_no - 1
      then (* retransmit *)
        Some (Packet.encode !seq_no !buf)
      else if (* if client up to date *)
              packet.seq_no == !last_sent_seq_no then (
        (* send new data *)
        let readBuf =
          let len = String.length (Domain_name.to_string domain) in
          (* only read what can fit in a domain name encoding *)
          Cstruct.create (Domain_name_data.max_encoded_len - len)
        in
        match Cstruct_stream.try_take out readBuf with
        | None -> Some (Packet.encode packet.seq_no Cstruct.empty)
        | Some r ->
            seq_no := !seq_no + 1;
            (* truncate buffer to the number of bytes read *)
            let readBuf = Cstruct.sub readBuf 0 r in
            (* save in case we need to retransmit *)
            buf := readBuf;
            last_sent_seq_no := !seq_no;
            Some (Packet.encode !seq_no readBuf))
      else (
        (* if client is somehow more than one packet out of date, or in the future *)
        Format.fprintf Format.err_formatter
          "Transport: invalid sequence number, sent %d but client last got %d\n"
          !last_sent_seq_no packet.seq_no;
        Format.pp_print_flush Format.err_formatter ();
        None)
    in

    let hostname = Domain_name_data.encode domain reply in
    let rr = Dns.Rr_map.singleton Dns.Rr_map.Cname (0l, hostname) in
    let answer = Domain_name.Map.singleton name rr in
    let authority = Dns.Name_rr_map.empty in
    let data = `Answer (answer, authority) in
    let additional = None in
    let flags = Dns.Packet.Flags.singleton `Authoritative in
    let packet =
      Dns.Packet.create ?additional (fst p.header, flags) p.question data
    in
    Some packet
  in

  Eio.Fiber.fork ~sw (fun () ->
      Dns_server_eio.primary env proto ~packet_callback server_state log
        addresses);
  Stream.create ~inc ~out
