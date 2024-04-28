module Server_state = struct
  type receiving_state = {
    packet : Frag_packet.packet;
    next_frag_nb : int;
    acc_frags : Cstruct.t list;
  }

  type sending_state = {
    packet : Frag_packet.packet;
    next_frag_nb : int;
    packet_data : Cstruct.t;
  }

  let receive (receiving_state_opt : receiving_state option)
      (frag_packet : Frag_packet.t) inc =
    (* ignore dummy packets *)
    match frag_packet with
    | Dummy _ -> receiving_state_opt
    | Packet frag_packet ->
        (* see if we need to reset recieving state *)
        let receiving_state =
          match receiving_state_opt with
          | None ->
              { packet = frag_packet.packet; next_frag_nb = 0; acc_frags = [] }
          | Some receiving_state ->
              (* If we're receiving a new fragment packet *)
              (* NB this may drop an old packet, we don't deal with out of order delivery *)
              if frag_packet.packet.id != receiving_state.packet.id then
                {
                  packet = frag_packet.packet;
                  next_frag_nb = 0;
                  acc_frags = [];
                }
              else receiving_state
        in
        (* if this is not the next fragment, ignore it, we don't deal with out of order delivery *)
        if frag_packet.frag_nb != receiving_state.next_frag_nb then
          Some receiving_state
        else
          let receiving_state =
            {
              receiving_state with
              acc_frags = frag_packet.data :: receiving_state.acc_frags;
              next_frag_nb = receiving_state.next_frag_nb + 1;
            }
          in
          if frag_packet.frag_nb != frag_packet.packet.n_frags - 1 then
            Some receiving_state
          else (
            Cstruct_stream.add inc
              [ Cstruct.concat (List.rev receiving_state.acc_frags) ];
            None)

  let send sending_state mtu out =
    let get_frag sending_state =
      let frag_buf =
        let offset = sending_state.next_frag_nb * mtu in
        Cstruct.sub sending_state.packet_data offset
          (min mtu (Cstruct.length sending_state.packet_data - offset))
      in
      let frag =
        Frag_packet.(
          Packet
            {
              packet = sending_state.packet;
              frag_nb = sending_state.next_frag_nb;
              data = frag_buf;
            })
      in
      let sending_state =
        if sending_state.next_frag_nb < sending_state.packet.n_frags - 1 then
          Some
            { sending_state with next_frag_nb = sending_state.next_frag_nb + 1 }
        else None
      in
      (sending_state, frag)
    in
    match sending_state with
    | Some sending_state -> get_frag sending_state
    | None -> (
        match Cstruct_stream.try_take_one out with
        | None -> (sending_state, Frag_packet.dummy 0)
        | Some packet ->
            let sending_state =
              {
                packet_data = packet;
                packet =
                  {
                    id = 1;
                    n_frags = (Cstruct.length packet + (mtu - 1)) / mtu;
                  };
                next_frag_nb = 0;
              }
            in
            get_frag sending_state)
end

(* TODO refactor and deduplicate these behemoths *)
let run ~sw env proto ~subdomain ~authorative server_state log addresses =
  let inc = Cstruct_stream.create () in
  let out = Cstruct_stream.create () in

  (* don't handle out of order transmission *)
  let receiving_state_ref : Server_state.receiving_state option ref =
    ref None
  in
  let sending_state_ref = ref None in
  (* we need a consistent MTU for fragmentation *)
  let mtu =
    (* String.length (subdomain ^ "." ^ authorative) *)
    let rootLen = String.length subdomain + 1 + String.length authorative in
    (* TODO figure out why our mtu calc is wrong *)
    Domain_name_data.max_encoded_len - rootLen - 20
  in

  let packet_callback (p : Dns.Packet.t) : Dns.Packet.t option =
    (* let state = !state_ref in *)
    let receiving_state = !receiving_state_ref
    and sending_state = !sending_state_ref in
    let ( let* ) = Option.bind in
    let* name, qtype =
      match p.Dns.Packet.data with `Query -> Some p.question | _ -> None
    in
    let* recv_buf, root = Domain_name_data.decode subdomain name in

    let* () =
      if String.lowercase_ascii (Domain_name.to_string root) = authorative then
        Some ()
      else (
        Eio.traceln "Ignoring query to authority %a" Domain_name.pp root;
        None)
    in
    let domain = Domain_name.prepend_label_exn root subdomain in

    (* Only process CNAME queries *)
    let* () =
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

    let frag_packet = Frag_packet.decode recv_buf in

    (* Update state, get reply *)
    let receiving_state =
      Server_state.receive receiving_state frag_packet inc
    in
    let sending_state, reply = Server_state.send sending_state mtu out in
    sending_state_ref := sending_state;
    receiving_state_ref := receiving_state;

    (* Build and return the packet *)
    let packet =
      let hostname = Domain_name_data.encode domain (Frag_packet.encode reply) in
      let rr = Dns.Rr_map.singleton Dns.Rr_map.Cname (0l, hostname) in
      let answer = Domain_name.Map.singleton name rr in
      let authority = Dns.Name_rr_map.empty in
      let data = `Answer (answer, authority) in
      let additional = None in
      let flags = Dns.Packet.Flags.singleton `Authoritative in
      Dns.Packet.create ?additional (fst p.header, flags) p.question data
    in
    Some packet
  in

  Eio.Fiber.fork ~sw (fun () ->
      Dns_server_eio.primary env proto ~packet_callback server_state log
        addresses);
  let send buf = Cstruct_stream.add out [ buf ]
  and recv buf = Cstruct_stream.take_one inc buf in
  Datagram.create send recv
