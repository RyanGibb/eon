type dns_datagram = { send : Cstruct.t -> unit; recv : Cstruct.t -> int }

(* rfc1035 section 2.3.4 *)
let max_name_len = 255
let max_label_len = 63

let max_encoded_len =
  (* subtract the characters needed for label delimination *)
  let max_name_non_label_len = max_name_len - (max_name_len / max_label_len) in
  (* as base64 encodes 6 bits in a byte, this gives us 3/4 of the `max_name_len` rounded up  *)
  1 + ((max_name_non_label_len - 1) / 4 * 3)

let buf_of_domain_name sudbomain name =
  let ( let* ) = Option.bind in
  let* i = Domain_name.find_label name (fun s -> String.equal sudbomain (String.lowercase_ascii s)) in
  let data_name = Domain_name.drop_label_exn ~rev:true ~amount:(Domain_name.count_labels name - i) name in
  let root = Domain_name.drop_label_exn ~amount:i name in
  let data_array = Domain_name.to_array data_name in
  let data = String.concat "" (Array.to_list data_array) in
  (* if there is no data encoded, return an empty buffer *)
  if String.length data == 0 then Some (Cstruct.empty, root)
  else
    try
      let cstruct = Cstruct.of_string @@ Base64.decode_exn data in
      Some (cstruct, root)
    with Invalid_argument e ->
      Format.fprintf Format.err_formatter "Transport: error decoding %s\n" e;
      Format.pp_print_flush Format.err_formatter ();
      None

let domain_name_of_buf root cstruct =
  let data = Base64.encode_exn @@ Cstruct.to_string cstruct in
  let authority = Domain_name.to_string root in
  (* String.length (data_subdomain ^ "." ^ authority) *)
  assert (String.length data + 1 + String.length authority <= max_name_len);
  let rec labels_of_string string =
    let len = String.length string in
    if len > max_label_len then
      let label = String.sub string 0 max_label_len in
      let string = String.sub string max_label_len (len - max_label_len) in
      let list = labels_of_string string in
      label :: list
    else [ string ]
  in
  let data_name = Array.of_list @@ labels_of_string data in
  let name_array = Array.append (Domain_name.to_array root) data_name in
  let hostname = Domain_name.of_array name_array in
  (* if the message is empty, just return the root *)
  if Cstruct.length cstruct == 0 then root else hostname

module Packet : sig
  type t = { (* for retransmissions *)
             seq_no : int; data : Cstruct.t }

  val decode : Cstruct.t -> t
  val encode : int -> Cstruct.t -> Cstruct.t
end = struct
  type t = { seq_no : int; data : Cstruct.t }

  let decode buf =
    let seq_no = Cstruct.BE.get_uint16 buf 0 in
    let data = Cstruct.sub buf 2 (Cstruct.length buf - 2) in
    { seq_no; data }

  let encode seq_no data =
    let buf = Cstruct.create (2 + Cstruct.length data) in
    Cstruct.BE.set_uint16 buf 0 seq_no;
    Cstruct.blit data 0 buf 2 (Cstruct.length data);
    buf
end

module UniquePacket : sig
  type t = {
    (* for uniqueness when encoding in query domain names *)
    id : int;
    (* for retransmissions *)
    seq_no : int;
    data : Cstruct.t;
  }

  val decode : Cstruct.t -> t
  val encode : int -> int -> Cstruct.t -> Cstruct.t
end = struct
  type t = { id : int; seq_no : int; data : Cstruct.t }

  let decode buf =
    let id = Cstruct.BE.get_uint16 buf 0 in
    let seq_no = Cstruct.BE.get_uint16 buf 2 in
    let data = Cstruct.sub buf 4 (Cstruct.length buf - 4) in
    { id; seq_no; data }

  let encode id seq_no data =
    let buf = Cstruct.create (4 + Cstruct.length data) in
    Cstruct.BE.set_uint16 buf 0 id;
    Cstruct.BE.set_uint16 buf 2 seq_no;
    Cstruct.blit data 0 buf 4 (Cstruct.length data);
    buf
end

module FragPacket : sig
  type packet = { id : int; n_frags : int  (** how many fragments to expect for this packet *) }
  type t = { packet : packet; frag_nb : int;  (** identifying fragment in packet *) data : Cstruct.t }

  val decode : Cstruct.t -> t
  val encode : t -> Cstruct.t
  val empty : packet_id:int -> t
end = struct
  type packet = { id : int; n_frags : int  (** how many fragments to expect for this packet *) }
  type t = { packet : packet; frag_nb : int; data : Cstruct.t }

  let empty ~packet_id = { packet = { id = packet_id; n_frags = 0 }; frag_nb = 0; data = Cstruct.empty }

  let decode buf =
    let id = Cstruct.BE.get_uint16 buf 0 in
    let frag_nb = Cstruct.BE.get_uint16 buf 2 in
    let n_frags = Cstruct.BE.get_uint16 buf 4 in
    let packet = { id; n_frags } in
    let data = Cstruct.sub buf 6 (Cstruct.length buf - 6) in
    { packet; frag_nb; data }

  let encode { packet; frag_nb; data } =
    let buf = Cstruct.create (6 + Cstruct.length data) in
    Cstruct.BE.set_uint16 buf 0 packet.id;
    Cstruct.BE.set_uint16 buf 2 frag_nb;
    Cstruct.BE.set_uint16 buf 4 packet.n_frags;
    Cstruct.blit data 0 buf 6 (Cstruct.length data);
    buf
end

module CstructStream : sig
  type t = { items : Cstruct.t list ref; mut : Eio.Mutex.t; cond : Eio.Condition.t }

  exception Empty

  val create : unit -> t
  val add : t -> Cstruct.t list -> unit
  val take : t -> Cstruct.t -> int
  val try_take : t -> Cstruct.t -> int option
  val take_one : t -> Cstruct.t -> int
  val try_take_one : t -> Cstruct.t option
end = struct
  type t = { items : Cstruct.t list ref; mut : Eio.Mutex.t; cond : Eio.Condition.t }

  exception Empty

  let create () = { items = ref []; mut = Eio.Mutex.create (); cond = Eio.Condition.create () }

  let add t bufs =
    Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
        t.items := !(t.items) @ bufs;
        Eio.Condition.broadcast t.cond)

  let take t buf =
    Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
        (* if `Cstruct.lenv !(t.items) == 0` we just send an empty packet *)
        while !(t.items) == [] do
          Eio.Condition.await t.cond t.mut
        done;
        let read, new_items = Cstruct.fillv ~src:!(t.items) ~dst:buf in
        t.items := new_items;
        read)

  let try_take q buf =
    let read, empty =
      Eio.Mutex.use_rw ~protect:false q.mut (fun () ->
          (* if `Cstruct.lenv !(q.items) == 0` we just send an empty packet *)
          if !(q.items) == [] then (0, true)
          else
            let read, new_items = Cstruct.fillv ~src:!(q.items) ~dst:buf in
            q.items := new_items;
            (read, false))
    in
    if empty then None else Some read

  let take_one t buf =
    Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
        let rec f () =
          match !(t.items) with
          | [] ->
              Eio.Condition.await t.cond t.mut;
              f ()
          | packet :: new_items ->
              let packet_len = Cstruct.length packet in
              (* will raise if buf isn't big enough to hold packet *)
              Cstruct.blit packet 0 buf 0 packet_len;
              t.items := new_items;
              packet_len
        in
        f ())

  let try_take_one t =
    Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
        match !(t.items) with
        | [] -> None
        | packet :: new_items ->
            t.items := new_items;
            Some packet)
end

let create_flow ~inc ~out =
  let module CstructFlow = struct
    type t = unit

    let copy _t ~src =
      let buf = Cstruct.create 4096 in
      try
        while true do
          let got = Eio.Flow.single_read src buf in
          CstructStream.add out [ Cstruct.sub buf 0 got ]
        done
      with End_of_file -> ()

    let single_write _t bufs =
      CstructStream.add out bufs;
      List.fold_left (fun acc buf -> acc + Cstruct.length buf) 0 bufs

    let read_methods = []
    let single_read _t buf = CstructStream.take inc buf
    let shutdown _t _cmd = ()
  end in
  let ops = Eio.Flow.Pi.two_way (module CstructFlow) in
  Eio.Resource.T ((), ops)

let dns_server_stream ~sw ~net ~clock ~mono_clock ~proto data_subdomain server_state log addresses =
  let inc = CstructStream.create () and out = CstructStream.create () in

  (* TODO mutex *)
  let last_recv_seq_no = ref (-1) and last_sent_seq_no = ref 0 and seq_no = ref 0 in

  let buf = ref Cstruct.empty in

  let packet_callback (p : Dns.Packet.t) : Dns.Packet.t option =
    let ( let* ) = Option.bind in
    let* name, qtype = match p.Dns.Packet.data with `Query -> Some p.question | _ -> None in
    let* recv_buf, root = buf_of_domain_name data_subdomain name in

    (* Only process CNAME queries *)
    let* _ =
      match qtype with
      | `K (Dns.Rr_map.K Dns.Rr_map.Cname) -> Some ()
      | `Axfr | `Ixfr ->
          Format.fprintf Format.err_formatter "Transport: unsupported operation zonetransfer\n";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `Any ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR ANY\n";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `K rr ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR %a\n" Dns.Rr_map.ppk rr;
          Format.pp_print_flush Format.err_formatter ();
          None
    in

    let packet = UniquePacket.decode recv_buf in

    let* reply =
      (* allow resetting stream *)
      (* TODO sessions *)
      (* TODO think about this a bit *)
      if packet.seq_no == 0 && Cstruct.length packet.data == 0 then (
        last_sent_seq_no := 0;
        seq_no := 0);

      (* if this is a data carrying packet, reply with an ack *)
      if Cstruct.length packet.data > 0 then (
        (* if we haven't already recieved this sequence number *)
        (* TODO a rogue packet from a bad actor could break this stream, or a delayed retransmission from a resolver *)
        if packet.seq_no != !last_recv_seq_no then CstructStream.add inc [ packet.data ];
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
          let rootLen = String.length (Domain_name.to_string root) in
          (* only read what can fit in a domain name encoding with root *)
          Cstruct.create (max_encoded_len - rootLen)
        in
        match CstructStream.try_take out readBuf with
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
        Format.fprintf Format.err_formatter "Transport: invalid sequence number, sent %d but client last got %d\n"
          !last_sent_seq_no packet.seq_no;
        Format.pp_print_flush Format.err_formatter ();
        None)
    in

    let hostname = domain_name_of_buf root reply in
    let rr = Dns.Rr_map.singleton Dns.Rr_map.Cname (0l, hostname) in
    let answer = Domain_name.Map.singleton name rr in
    let authority = Dns.Name_rr_map.empty in
    let data = `Answer (answer, authority) in
    let additional = None in
    let flags = Dns.Packet.Flags.singleton `Authoritative in
    let packet = Dns.Packet.create ?additional (fst p.header, flags) p.question data in
    Some packet
  in

  Eio.Fiber.fork ~sw (fun () ->
      Dns_server_eio.primary ~net ~clock ~mono_clock ~proto ~packet_callback server_state log addresses);
  create_flow ~inc ~out

let dns_client_stream ~sw ~net ~clock ~random nameserver data_subdomain authority port log =
  let inc = CstructStream.create () and out = CstructStream.create () in

  (* TODO support different queries, or probing access *)
  let record_type = Dns.Rr_map.Cname
  and addr =
    match Eio.Net.getaddrinfo_datagram net ~service:(Int.to_string port) nameserver with
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
    match buf_of_domain_name data_subdomain cname with
    | None -> exit 1
    | Some (recv_buf, _root) ->
        let packet = Packet.decode recv_buf in
        if Cstruct.length packet.data > 0 then
          Eio.Mutex.use_rw recv_data_mut ~protect:false (fun () ->
              (* if we haven't already recieved this sequence number *)
              if !last_recv_seq_no != packet.seq_no then (
                CstructStream.add inc [ packet.data ];
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
    Eio.Net.datagram_socket ~sw net proto
  in
  let root = Domain_name.of_strings_exn (data_subdomain :: String.split_on_char '.' authority) in
  let get_id () =
    Cstruct.LE.get_uint16
      (let b = Cstruct.create 2 in
       Eio.Flow.read_exact random b;
       b)
      0
  in
  let send_data_fiber () =
    let buf =
      (* String.length (data_subdomain ^ "." ^ authority) *)
      let rootLen = String.length data_subdomain + 1 + String.length authority in
      Cstruct.create (max_encoded_len - rootLen - 20)
    in
    while true do
      let read = CstructStream.take out buf in
      (* truncate buffer to the number of bytes read *)
      let buf = Cstruct.sub buf 0 read in
      Eio.Mutex.use_rw acked_mut ~protect:false (fun () ->
          (* increment before so it can be used to check recieved packets *)
          seq_no := !seq_no + 1;
          let sent_seq_no = !seq_no in
          let reply_buf = UniquePacket.encode !id sent_seq_no buf in
          id := !id + 1;
          let hostname = domain_name_of_buf root reply_buf in
          (* retransmit *)
          while !last_acked_seq_no != sent_seq_no do
            Dns_client_eio.send_query log (get_id ()) record_type hostname sock addr;
            ignore
            @@ Eio.Time.with_timeout clock 1. (fun () ->
                   Eio.Condition.await acked acked_mut;
                   Ok ())
          done)
    done
  in
  let send_empty_query_fiber () =
    while true do
      Eio.Mutex.use_rw recv_data_mut ~protect:false (fun () ->
          (* sent a packet with the last recieved sequence number *)
          let reply_buf = UniquePacket.encode !id !last_recv_seq_no Cstruct.empty in
          id := !id + 1;
          let hostname = domain_name_of_buf root reply_buf in

          Dns_client_eio.send_query log (get_id ()) record_type hostname sock addr;
          ignore
          @@ Eio.Time.with_timeout clock 1. (fun () ->
                 Eio.Condition.await recv_data recv_data_mut;
                 Ok ()))
    done
  in
  Eio.Fiber.fork ~sw (fun () -> Dns_client_eio.listen sock log handle_dns ());
  Eio.Fiber.fork ~sw (fun () -> send_data_fiber ());
  Eio.Fiber.fork ~sw (fun () -> send_empty_query_fiber ());
  create_flow ~inc ~out

module Server_state = struct
  type receiving_state = { packet : FragPacket.packet; next_frag_nb : int; acc_frags : Cstruct.t list }
  type sending_state = { packet : FragPacket.packet; next_frag_nb : int; packet_data : Cstruct.t }

  let receive (receiving_state : receiving_state option) (frag_packet : FragPacket.t) inc =
    match receiving_state with
    | None -> None
    | Some receiving_state ->
        let receiving_state =
          (* If we're receiving a new fragment packet *)
          (* NB this may drop an old packet, we don't deal with out of order delivery *)
          if Cstruct.length frag_packet.data > 0 && frag_packet.packet.id != receiving_state.packet.id then
            { packet = frag_packet.packet; next_frag_nb = 0; acc_frags = [] }
          else receiving_state
        in
        if frag_packet.frag_nb == receiving_state.next_frag_nb then
          let receiving_state =
            {
              receiving_state with
              acc_frags = frag_packet.data :: receiving_state.acc_frags;
              next_frag_nb = receiving_state.next_frag_nb + 1;
            }
          in
          if frag_packet.frag_nb != frag_packet.packet.n_frags - 1 then Some receiving_state
          else (
            CstructStream.add inc [ Cstruct.concat (List.rev receiving_state.acc_frags) ];
            None)
        else Some receiving_state

  let send sending_state mtu out =
    let get_frag sending_state =
      let frag_buf =
        let offset = sending_state.next_frag_nb * mtu in
        Cstruct.sub sending_state.packet_data offset (min mtu (Cstruct.length sending_state.packet_data - offset))
      in
      let frag = FragPacket.{ packet = sending_state.packet; frag_nb = sending_state.next_frag_nb; data = frag_buf } in
      let sending_state =
        if sending_state.next_frag_nb < sending_state.packet.n_frags - 1 then
          Some { sending_state with next_frag_nb = sending_state.next_frag_nb + 1 }
        else None
      in
      (sending_state, frag)
    in
    match sending_state with
    | Some sending_state -> get_frag sending_state
    | None -> (
        match CstructStream.try_take_one out with
        | None -> (sending_state, FragPacket.empty ~packet_id:0)
        | Some packet ->
            let sending_state =
              {
                packet_data = packet;
                packet = { id = 1; n_frags = (Cstruct.length packet + (mtu - 1)) / mtu };
                next_frag_nb = 0;
              }
            in
            get_frag sending_state)
end

(* TODO refactor and deduplicate these behemoths *)
let dns_server_datagram ~sw ~net ~clock ~mono_clock ~proto data_subdomain authority server_state log addresses =
  let inc = CstructStream.create () in
  let out = CstructStream.create () in

  (* don't handle out of order transmission *)
  let receiving_state_ref : Server_state.receiving_state option ref = ref None in
  let sending_state_ref = ref None in
  let mtu =
    (* String.length (data_subdomain ^ "." ^ authority) *)
    let rootLen = String.length data_subdomain + 1 + String.length authority in
    max_encoded_len - rootLen - 20
  in

  let packet_callback (p : Dns.Packet.t) : Dns.Packet.t option =
    (* let state = !state_ref in *)
    let receiving_state = !receiving_state_ref and sending_state = !sending_state_ref in
    let ( let* ) = Option.bind in
    let* name, qtype = match p.Dns.Packet.data with `Query -> Some p.question | _ -> None in
    let* recv_buf, root = buf_of_domain_name data_subdomain name in

    assert (String.lowercase_ascii (Domain_name.to_string root) = authority);

    (* Only process CNAME queries *)
    let* () =
      match qtype with
      | `K (Dns.Rr_map.K Dns.Rr_map.Cname) -> Some ()
      | `Axfr | `Ixfr ->
          Format.fprintf Format.err_formatter "Transport: unsupported operation zonetransfer\n";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `Any ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR ANY\n";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `K rr ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR %a\n" Dns.Rr_map.ppk rr;
          Format.pp_print_flush Format.err_formatter ();
          None
    in

    let frag_packet = FragPacket.decode recv_buf in

    (* Update state, get reply *)
    let receiving_state = Server_state.receive receiving_state frag_packet inc in
    let sending_state, reply = Server_state.send sending_state mtu out in
    sending_state_ref := sending_state;
    receiving_state_ref := receiving_state;

    (* Build and return the packet *)
    let packet =
      let hostname = domain_name_of_buf root (FragPacket.encode reply) in
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
      Dns_server_eio.primary ~net ~clock ~mono_clock ~proto ~packet_callback server_state log addresses);
  { send = (fun buf -> CstructStream.add out [ buf ]); recv = (fun buf -> CstructStream.take_one inc buf) }

module Client_state = struct
  type client_state = {
    current_packet : FragPacket.packet;  (** The id of the packet we are currently receiving *)
    acc_frags : Cstruct.t list;  (** The list of data received so far (most recent first) *)
    next_frag_nb : int;  (** The nb of the next fragment we are expecting *)
  }

  let receive state (frag : FragPacket.t) (inc : CstructStream.t) =
    let state =
      match state with
      | None -> { current_packet = frag.packet; next_frag_nb = 0; acc_frags = [] }
      | Some state ->
          (* If we're receiving a new fragment packet *)
          (* NB this may drop an old packet, we don't deal with out of order delivery *)
          if frag.packet.id != state.current_packet.id then
            { current_packet = frag.packet; next_frag_nb = 0; acc_frags = [] }
          else state
    in
    Eio.traceln "IN_FRAG id %d no %d t %d" frag.packet.id frag.frag_nb frag.packet.n_frags;
    if frag.frag_nb != state.next_frag_nb then Some state
    else
      let state = { state with acc_frags = frag.data :: state.acc_frags; next_frag_nb = state.next_frag_nb + 1 } in
      if frag.frag_nb != frag.packet.n_frags - 1 then Some state
      else
        let reconsituted_data = Cstruct.concat (List.rev state.acc_frags) in
        inc.items := reconsituted_data :: !(inc.items);
        Eio.Condition.broadcast inc.cond;
        None
end

let dns_client_datagram ~sw ~net ~clock ~random nameserver data_subdomain authority port log =
  let inc = CstructStream.create () in

  (* TODO support different queries, or probing access *)
  let record_type = Dns.Rr_map.Cname
  and addr =
    match Eio.Net.getaddrinfo_datagram net ~service:(Int.to_string port) nameserver with
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
    match buf_of_domain_name data_subdomain cname with
    | None -> exit 1
    | Some (recv_buf, _root) ->
        if Cstruct.length recv_buf = 0 then state
        else
          let frag = FragPacket.decode recv_buf in
          if Cstruct.length frag.data = 0 then state
          else Eio.Mutex.use_rw inc.mut ~protect:false (fun () -> Client_state.receive state frag inc)
  in
  let sock =
    let proto =
      match addr with
      | `Udp (ipaddr, _p) -> Eio.Net.Ipaddr.fold ~v4:(fun _v4 -> `UdpV4) ~v6:(fun _v6 -> `UdpV6) ipaddr
      | `Unix _ -> failwith "unix domain sockets unsupported"
    in
    Eio.Net.datagram_socket ~sw net proto
  in
  let root = Domain_name.of_strings_exn (data_subdomain :: String.split_on_char '.' authority) in
  let get_id () =
    Cstruct.LE.get_uint16
      (let b = Cstruct.create 2 in
       Eio.Flow.read_exact random b;
       b)
      0
  in
  let send_empty_query_fiber () =
    while true do
      Eio.Mutex.use_rw inc.mut ~protect:false (fun () ->
          (* sent a packet with a random id and hope that it doesn't collide *)
          let frag = FragPacket.empty ~packet_id:(get_id ()) in
          let reply_buf = FragPacket.encode frag in
          let hostname = domain_name_of_buf root reply_buf in

          Dns_client_eio.send_query log (get_id ()) record_type hostname sock addr;
          ignore
          @@ Eio.Time.with_timeout clock 2. (fun () ->
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
      (* String.length (data_subdomain ^ "." ^ authority) *)
      let rootLen = String.length data_subdomain + 1 + String.length authority in
      max_encoded_len - rootLen - 20
    in
    let id = new_id () in
    let n_frags = (buf_len + (mtu - 1)) / mtu in
    for frag_nb = 0 to n_frags do
      let packet =
        let data =
          let offset = frag_nb * mtu in
          Cstruct.sub buf offset (min mtu (buf_len - offset))
        in
        let open FragPacket in
        let packet = { id; n_frags } in
        let frag = { packet; frag_nb; data } in
        encode frag
      in
      let hostname = domain_name_of_buf root packet in
      Eio.traceln "OUT_FRAG id %d no %d t %d" id frag_nb n_frags;
      Dns_client_eio.send_query log (get_id ()) record_type hostname sock addr
    done
  in
  let recv buf = CstructStream.take_one inc buf in
  { send; recv }
