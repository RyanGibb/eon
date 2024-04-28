module Client_state = struct
  type client_state = {
    current_packet : Frag_packet.packet;
        (** The id of the packet we are currently receiving *)
    acc_frags : Cstruct.t list;
        (** The list of data received so far (most recent first) *)
    next_frag_nb : int;  (** The nb of the next fragment we are expecting *)
  }

  let receive state (frag : Frag_packet.t) (inc : Cstruct_stream.t) =
    match frag with
    | Dummy _ -> state
    | Packet frag ->
        let state =
          match state with
          | None ->
              { current_packet = frag.packet; next_frag_nb = 0; acc_frags = [] }
          | Some state ->
              (* If we're receiving a new fragment packet *)
              (* NB this may drop an old packet, we don't deal with out of order delivery *)
              if frag.packet.id != state.current_packet.id then
                {
                  current_packet = frag.packet;
                  next_frag_nb = 0;
                  acc_frags = [];
                }
              else state
        in
        Eio.traceln "IN_FRAG id %d no %d t %d" frag.packet.id frag.frag_nb
          frag.packet.n_frags;
        if frag.frag_nb != state.next_frag_nb then Some state
        else
          let state =
            {
              state with
              acc_frags = frag.data :: state.acc_frags;
              next_frag_nb = state.next_frag_nb + 1;
            }
          in
          if frag.frag_nb != frag.packet.n_frags - 1 then Some state
          else
            let reconsituted_data = Cstruct.concat (List.rev state.acc_frags) in
            inc.items := reconsituted_data :: !(inc.items);
            Eio.Condition.broadcast inc.cond;
            None
end

let run ~sw env ~nameserver ~subdomain ~authorative port log timeout =
  let inc = Cstruct_stream.create () in

  (* TODO support different queries, or probing access *)
  let record_type = Dns.Rr_map.Cname
  and addr =
    match
      Eio.Net.getaddrinfo_datagram env#net ~service:(Int.to_string port)
        nameserver
    with
    (* just takes first returned value, which is probably ipv6 *)
    | ipaddr :: _ -> ipaddr
    | [] ->
        Format.fprintf Format.err_formatter "Invalid address: %s\n" nameserver;
        Format.pp_print_flush Format.err_formatter ();
        exit 1
  in

  (* don't handle out of order transmission *)
  (* frag_id = 0 means we're not processing any currently *)
  let state = None in
  let handle_dns _proto _addr buf state =
    let open Option in
    let ( let* ) o f = match o with None -> state | Some v -> f v in
    let packet =
      match Dns.Packet.decode buf with
      | Ok packet -> packet
      | Error err ->
          Format.fprintf Format.err_formatter "Transport: error decoding %a\n"
            Dns.Packet.pp_err err;
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
    match Domain_name_data.decode subdomain cname with
    | None -> exit 1
    | Some (recv_buf, _root) ->
        if Cstruct.length recv_buf = 0 then state
        else
          let frag = Frag_packet.decode recv_buf in
          Eio.Mutex.use_rw inc.mut ~protect:false (fun () ->
              Client_state.receive state frag inc)
  in
  let sock =
    let proto =
      match addr with
      | `Udp (ipaddr, _p) ->
          Eio.Net.Ipaddr.fold
            ~v4:(fun _v4 -> `UdpV4)
            ~v6:(fun _v6 -> `UdpV6)
            ipaddr
      | `Unix _ -> failwith "unix domain sockets unsupported"
    in
    Eio.Net.datagram_socket ~sw env#net proto
  in
  let root =
    Domain_name.of_strings_exn
      (subdomain :: String.split_on_char '.' authorative)
  in
  let get_id () =
    Cstruct.LE.get_uint16
      (let b = Cstruct.create 2 in
       Eio.Flow.read_exact env#secure_random b;
       b)
      0
  in
  let send_empty_query_fiber () =
    while true do
      Eio.Mutex.use_rw inc.mut ~protect:false (fun () ->
          (* sent a packet with a random id and hope that it doesn't collide *)
          let frag = Frag_packet.dummy (get_id ()) in
          let reply_buf = Frag_packet.encode frag in
          let hostname = Domain_name_data.encode root reply_buf in

          Dns_client_eio.send_query log (get_id ()) record_type hostname sock
            addr;
          ignore
          @@ Eio.Time.with_timeout env#clock timeout (fun () ->
                 Eio.Condition.await inc.cond inc.mut;
                 Ok ()));
      Eio.Fiber.yield ()
    done
  in
  Eio.Fiber.fork ~sw (fun () -> Dns_client_eio.listen sock log handle_dns state);
  Eio.Fiber.fork ~sw (fun () -> send_empty_query_fiber ());

  let new_id =
    let id = ref 0 in
    fun () ->
      incr id;
      !id - 1
  in
  let send buf =
    let buf_len = Cstruct.length buf in
    let mtu =
      (* String.length (subdomain ^ "." ^ authorative) *)
      let rootLen = String.length subdomain + 1 + String.length authorative in
      (* TODO figure out why our mtu calc is wrong *)
      Domain_name_data.max_encoded_len - rootLen - 20
    in
    let id = new_id () in
    let n_frags = (buf_len + (mtu - 1)) / mtu in
    for frag_nb = 0 to n_frags - 1 do
      let packet =
        let data =
          let offset = frag_nb * mtu in
          Cstruct.sub buf offset (min mtu (buf_len - offset))
        in
        let open Frag_packet in
        let packet = { id; n_frags } in
        let frag = Packet { packet; frag_nb; data } in
        encode frag
      in
      let hostname = Domain_name_data.encode root packet in
      Eio.traceln "OUT_FRAG id %d no %d t %d" id frag_nb n_frags;
      Dns_client_eio.send_query log (get_id ()) record_type hostname sock addr
    done
  in
  let recv buf = Cstruct_stream.take_one inc buf in
  Datagram.create send recv
