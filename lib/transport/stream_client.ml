let run ~sw env nameserver data_subdomain authority port log timeout =
  let inc = Cstruct_stream.create () and out = Cstruct_stream.create () in

  (* TODO support different queries, or probing access *)
  let record_type = Dns.Rr_map.Cname
  and addr =
    match Eio.Net.getaddrinfo_datagram env#net ~service:(Int.to_string port) nameserver with
    (* just takes first returned value, which is probably ipv6 *)
    | ipaddr :: _ -> ipaddr
    | [] ->
        Format.fprintf Format.err_formatter "Invalid address: %s\n" nameserver;
        Format.pp_print_flush Format.err_formatter ();
        exit 1
  in

  let recv_data_mut = Eio.Mutex.create ()
  and recv_data = Eio.Condition.create ()
  and acked_mut = Eio.Mutex.create ()
  and acked = Eio.Condition.create ()
  and last_acked_seq_no = ref (-1)
  and last_recv_seq_no = ref 0
  and seq_no = ref (-1)
  and id = ref 0 in

  (* TODO handle state like for datagram *)
  let handle_dns _proto _addr buf () : unit =
    let ( let* ) o f = match o with None -> () | Some v -> f v in
    let* packet =
      match Dns.Packet.decode buf with
      | Ok packet -> Some packet
      | Error err ->
          Format.fprintf Format.err_formatter "Transport: error decoding %a\n" Dns.Packet.pp_err err;
          Format.pp_print_flush Format.err_formatter ();
          exit 1
    in
    let* answer =
      match packet.data with
      | `Answer (answer, _authority) -> Some answer
      (* ignore server failure (likely due to a timeout) *)
      | `Rcode_error (Dns.Rcode.ServFail, Dns.Opcode.Query, _) -> None
      | _ ->
          Format.fprintf Format.err_formatter "Transport: no answer section\n";
          Format.pp_print_flush Format.err_formatter ();
          exit 1
    in
    let* map =
      match Domain_name.Map.bindings answer with
      | [ (_key, map) ] -> Some map
      | _ ->
          Format.fprintf Format.err_formatter "Transport: no answer\n";
          Format.pp_print_flush Format.err_formatter ();
          exit 1
    in
    let* _ttl, cname = Dns.Rr_map.find record_type map in
    match Domain_name_data.decode data_subdomain cname with
    | None -> exit 1
    | Some (recv_buf, _root) ->
        let packet = Packet.decode recv_buf in
        if Cstruct.length packet.data > 0 then
          Eio.Mutex.use_rw recv_data_mut ~protect:false (fun () ->
              (* if we haven't already recieved this sequence number *)
              if !last_recv_seq_no != packet.seq_no then (
                Cstruct_stream.add inc [ packet.data ];
                last_recv_seq_no := packet.seq_no;
                Eio.Condition.broadcast recv_data))
        else
          Eio.Mutex.use_rw acked_mut ~protect:false (fun () ->
              (* ignore if this not the ack for the most recent data packet *)
              if !seq_no == packet.seq_no then (
                Eio.Condition.broadcast acked;
                last_acked_seq_no := packet.seq_no))
  in

  let sock =
    let proto =
      match addr with
      | `Udp (ipaddr, _p) -> Eio.Net.Ipaddr.fold ~v4:(fun _v4 -> `UdpV4) ~v6:(fun _v6 -> `UdpV6) ipaddr
      | `Unix _ -> failwith "unix domain sockets unsupported"
    in
    Eio.Net.datagram_socket ~sw env#net proto
  in
  let root = Domain_name.of_strings_exn (data_subdomain :: String.split_on_char '.' authority) in
  let get_id () =
    Cstruct.LE.get_uint16
      (let b = Cstruct.create 2 in
       Eio.Flow.read_exact env#secure_random b;
       b)
      0
  in
  let send_data_fiber () =
    let buf =
      (* String.length (data_subdomain ^ "." ^ authority) *)
      let rootLen = String.length data_subdomain + 1 + String.length authority in
      (* TODO figure out why our mtu calc is wrong *)
      Cstruct.create (Domain_name_data.max_encoded_len - rootLen - 20)
    in
    while true do
      let read = Cstruct_stream.take out buf in
      (* truncate buffer to the number of bytes read *)
      let buf = Cstruct.sub buf 0 read in
      Eio.Mutex.use_rw acked_mut ~protect:false (fun () ->
          (* increment before so it can be used to check recieved packets *)
          seq_no := !seq_no + 1;
          let sent_seq_no = !seq_no in
          let reply_buf = Unique_packet.encode !id sent_seq_no buf in
          id := !id + 1;
          let hostname = Domain_name_data.encode root reply_buf in
          (* retransmit *)
          while !last_acked_seq_no != sent_seq_no do
            Dns_client_eio.send_query log (get_id ()) record_type hostname sock addr;
            ignore
            @@ Eio.Time.with_timeout env#clock timeout (fun () ->
                   Eio.Condition.await acked acked_mut;
                   Ok ())
          done)
    done
  in
  let send_empty_query_fiber () =
    while true do
      Eio.Mutex.use_rw recv_data_mut ~protect:false (fun () ->
          (* sent a packet with the last recieved sequence number *)
          let reply_buf = Unique_packet.encode !id !last_recv_seq_no Cstruct.empty in
          id := !id + 1;
          let hostname = Domain_name_data.encode root reply_buf in

          Dns_client_eio.send_query log (get_id ()) record_type hostname sock addr;
          ignore
          @@ Eio.Time.with_timeout env#clock timeout (fun () ->
                 Eio.Condition.await recv_data recv_data_mut;
                 Ok ()))
    done
  in
  Eio.Fiber.fork ~sw (fun () -> Dns_client_eio.listen sock log handle_dns ());
  Eio.Fiber.fork ~sw (fun () -> send_data_fiber ());
  Eio.Fiber.fork ~sw (fun () -> send_empty_query_fiber ());
  Stream.create ~inc ~out
