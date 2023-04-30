class virtual dns_flow =
  object
    inherit Eio.Flow.two_way
  end

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
  let* i = Domain_name.find_label name (fun s -> String.equal sudbomain s) in
  let data_name =
    Domain_name.drop_label_exn ~rev:true
      ~amount:(Domain_name.count_labels name - i)
      name
  in
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
  assert (String.length data + 1 + String.length authority < max_name_len);
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
  type t = { seq_no : int; data : Cstruct.t }

  val decode : Cstruct.t -> t
  val encode : int -> Cstruct.t -> Cstruct.t
end = struct
  type t = {
    (* The only purpose of the sequence number at present is to make the encoded domain name unique.
       This prevents a result caching the result of an empty query. *)
    seq_no : int;
    data : Cstruct.t
  }

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

module CstructStream : sig
  type t

  exception Empty

  val create : unit -> t
  val add : t -> Cstruct.t list -> unit
  val cancel_waiters : t -> unit
  val take : t -> Cstruct.t -> int
  val take_cancellable : t -> Cstruct.t -> int option
  val to_flow : t -> t -> Eio.Flow.two_way
end = struct
  type t = {
    (* As `Cstruct.*v` functions take a `Cstruct.t list` *)
    items : Cstruct.t list ref;
    mut : Eio.Mutex.t;
    cond : Eio.Condition.t;
    waiters : int ref;
    cancel : bool ref;
  }

  exception Empty

  let create () =
    {
      items = ref [];
      mut = Eio.Mutex.create ();
      cond = Eio.Condition.create ();
      waiters = ref 0;
      cancel = ref false;
    }

  let add t bufs =
    Eio.Mutex.use_rw t.mut ~protect:true (fun () ->
        t.items := !(t.items) @ bufs;
        Eio.Condition.broadcast t.cond)

  let cancel_waiters t =
    Eio.Mutex.use_rw t.mut ~protect:true (fun () ->
        while !(t.waiters) > 0 do
          t.cancel := true;
          Eio.Condition.broadcast t.cond;
          (* yield with unlocked mutex to allow waiters to be cancelled *)
          Eio.Mutex.unlock t.mut;
          Eio.Fiber.yield ();
          Eio.Mutex.lock t.mut
        done;
        t.cancel := false)

  let take t buf =
    Eio.Mutex.use_rw t.mut ~protect:true (fun () ->
        t.waiters := !(t.waiters) + 1;
        (* if `Cstruct.lenv !(t.items) == 0` we just send an empty packet *)
        while !(t.items) == [] do
          Eio.Condition.await t.cond t.mut
        done;
        t.waiters := !(t.waiters) - 1;
        let read, new_items = Cstruct.fillv ~src:!(t.items) ~dst:buf in
        t.items := new_items;
        read)

  let take_cancellable t buf =
    Eio.Mutex.use_rw t.mut ~protect:true (fun () ->
        t.waiters := !(t.waiters) + 1;
        (* if `Cstruct.lenv !(t.items) == 0` we just send an empty packet *)
        while !(t.items) == [] && not !(t.cancel) do
          Eio.Condition.await t.cond t.mut
        done;
        t.waiters := !(t.waiters) - 1;
        if !(t.cancel) then None
        else
          let read, new_items = Cstruct.fillv ~src:!(t.items) ~dst:buf in
          t.items := new_items;
          Some read)

  let to_flow inc out =
    object (self : < Eio.Flow.source ; Eio.Flow.sink ; .. >)
      method probe : type a. a Eio.Generic.ty -> a option = function _ -> None

      method copy src =
        let buf = Cstruct.create 4096 in
        try
          while true do
            let got = Eio.Flow.single_read src buf in
            self#write [ Cstruct.sub buf 0 got ]
          done
        with End_of_file -> ()

      method write bufs = add out bufs
      method read_methods = []
      method read_into buf = take inc buf
      method shutdown _cmd = ()
    end
end

let dns_server ~sw ~net ~clock ~mono_clock ~tcp ~udp data_subdomain server_state
    log addresses =
  let server_inc = CstructStream.create ()
  and server_out = CstructStream.create () in

  let last_recv_data_id = ref 0
  and last_sent_data_id = ref 0
  and last_recv_empty_id = ref 0 in
  (* TODO mutex *)
  let seq_no = ref 0 in

  let buf = Cstruct.create max_encoded_len in
  let bufLen = ref 0 in

  let packet_callback (p : Dns.Packet.t) : Dns.Packet.t option =
    let ( let* ) = Option.bind in
    let* name, qtype =
      match p.Dns.Packet.data with `Query -> Some p.question | _ -> None
    in
    let* recv_buf, root = buf_of_domain_name data_subdomain name in
    let id, _flags = p.header in

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

    let packet = Packet.decode recv_buf in
    seq_no := max packet.seq_no !seq_no;

    let reply =
      (* if this is a data carrying packet, reply with an ack *)
      if Cstruct.length packet.data > 0 then (
        (* if we haven't already recieved this id *)
        (* TODO a rogue packet from a bad actor could break this stream, or a delayed retransmission from a resolver *)
        if !last_recv_data_id != id then
          CstructStream.add server_inc [ packet.data ];
        last_recv_data_id := id;
        (* an ack is a packet carrying no data *)
        Cstruct.empty)
      else if !last_sent_data_id == id then
        (* if this is a duplicate id, retransmit *)
        Cstruct.sub buf 0 !bufLen
      else if
        (* if there's already a thread waiting on data to reply to this query *)
        !last_recv_empty_id == id
      then Cstruct.empty
        (* otherwise, send new data *)

        (* TODO a rogue packet from a bad actor could break this stream, or a delayed retransmission from a resolver,
            by making the server not retransmit when it's required.
            We need a way to muliplex client streams.
            We could do by client socket address, but that would prevent mobility. *)
      else (
        last_recv_empty_id := id;
        (* if it's not the same id, cancel it *)
        CstructStream.cancel_waiters server_out;

        let readBuf =
          (* truncate buffer to only read what can fit in a domain name encoding with root *)
          let rootLen = String.length (Domain_name.to_string root) in
          Cstruct.sub buf 0 (max_encoded_len - rootLen)
        in
        let read =
          match CstructStream.take_cancellable server_out readBuf with
          | Some r -> r
          | None -> 0
        in
        bufLen := read;
        last_sent_data_id := id;
        (* truncate buffer to the number of bytes read *)
        Cstruct.sub readBuf 0 read)
    in

    let reply_buf = Packet.encode !seq_no reply in
    seq_no := !seq_no + 1;
    let hostname = domain_name_of_buf root reply_buf in
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
      Server.start ~net ~clock ~mono_clock ~tcp ~udp ~packet_callback
        server_state log addresses);
  CstructStream.to_flow server_inc server_out

let dns_client ~sw ~net ~clock ~random nameserver data_subdomain authority port
    log =
  let client_inc = CstructStream.create ()
  and client_out = CstructStream.create () in

  (* TODO support different queries, or probing access *)
  let record_type = Dns.Rr_map.Cname
  and addr =
    match
      Eio.Net.getaddrinfo_datagram net ~service:(Int.to_string port) nameserver
    with
    (* just takes first returned value, which is probably ipv6 *)
    | ipaddr :: _ -> ipaddr
    | [] ->
        Format.fprintf Format.err_formatter "Invalid address: %s\n" nameserver;
        Format.pp_print_flush Format.err_formatter ();
        exit 1
  in

  (* TODO mutexes? *)
  let recv_data_mut = Eio.Mutex.create ()
  and recv_empty_mut = Eio.Mutex.create () in
  let last_recv_empty_id = ref 0
  and last_recv_data_id = ref 0
  and last_sent_data_id = ref 0 in
  let recv_data = Eio.Condition.create ()
  and recv_empty = Eio.Condition.create () in
  (* TODO mutex *)
  let seq_no = ref 0 in

  let handle_dns _proto _addr buf : unit =
    let ( let* ) o f = match o with None -> () | Some v -> f v in
    let* packet =
      match Dns.Packet.decode buf with
      | Ok packet -> Some packet
      | Error err ->
          Format.fprintf Format.err_formatter "Transport: error decoding %a\n"
            Dns.Packet.pp_err err;
          Format.pp_print_flush Format.err_formatter ();
          None
    in
    let id, _flags = packet.header in
    let* answer =
      match packet.data with
      | `Answer (answer, _authority) -> Some answer
      | _ ->
          Format.fprintf Format.err_formatter "Transport: no answer section\n";
          Format.pp_print_flush Format.err_formatter ();
          None
    in
    let* map =
      match Domain_name.Map.bindings answer with
      | [ (_key, map) ] -> Some map
      | _ ->
          Format.fprintf Format.err_formatter "Transport: no answer\n";
          Format.pp_print_flush Format.err_formatter ();
          None
    in
    let* _ttl, cname = Dns.Rr_map.find record_type map in
    match buf_of_domain_name data_subdomain cname with
    | None -> exit 1
    | Some (recv_buf, _root) ->
        let packet = Packet.decode recv_buf in
        seq_no := max packet.seq_no !seq_no;
        if Cstruct.length packet.data > 0 then
          Eio.Mutex.use_rw recv_data_mut ~protect:true (fun () ->
              (* if we haven't already recieved this id *)
              if !last_recv_data_id != id then
                CstructStream.add client_inc [ packet.data ];
              last_recv_data_id := id;
              Eio.Condition.broadcast recv_data)
        else
          Eio.Mutex.use_rw recv_empty_mut ~protect:true (fun () ->
              (* ignore if this not the ack for the most recent data packet *)
              if id == !last_sent_data_id then (
                last_recv_empty_id := id;
                Eio.Condition.broadcast recv_empty))
  in
  let sock =
    let proto =
      match addr with
      | `Udp (ipaddr, _p) ->
          Eio.Net.Ipaddr.fold
            ~v4:(fun _v4 -> `UdpV4)
            ~v6:(fun _v6 -> `UdpV6)
            ipaddr
    in
    Eio.Net.datagram_socket ~sw net proto
  in
  let root =
    Domain_name.of_strings_exn
      (data_subdomain :: String.split_on_char '.' authority)
  in
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
      let rootLen =
        String.length data_subdomain + 1 + String.length authority
      in
      Cstruct.create (max_encoded_len - rootLen)
    in
    while true do
      let read = CstructStream.take client_out buf in
      (* truncate buffer to the number of bytes read *)
      let buf = Cstruct.sub buf 0 read in
      let reply_buf = Packet.encode !seq_no buf in
      seq_no := !seq_no + 1;
      let hostname = domain_name_of_buf root reply_buf in
      let id = get_id () in
      Eio.Mutex.use_rw recv_empty_mut ~protect:true (fun () ->
          last_sent_data_id := id;
          (* retransmit *)
          while id != !last_recv_empty_id do
            Client.send_query log id record_type hostname sock addr;
            ignore
            @@ Eio.Time.with_timeout clock 1. (fun () ->
                   Eio.Condition.await recv_empty recv_empty_mut;
                   Ok ())
          done)
    done
  in
  let send_empty_query_fiber () =
    while true do
      let id = get_id () in

      Eio.Mutex.use_rw recv_data_mut ~protect:true (fun () ->
          while id != !last_recv_data_id do

            let reply_buf = Packet.encode !seq_no Cstruct.empty in
            seq_no := !seq_no + 1;
            let hostname = domain_name_of_buf root reply_buf in

            Client.send_query log id record_type hostname sock addr;
            ignore
            @@ Eio.Time.with_timeout clock 1. (fun () ->
                   Eio.Condition.await recv_data recv_data_mut;
                   Ok ())
          done)
    done
  in
  Eio.Fiber.fork ~sw (fun () -> Client.listen sock log handle_dns);
  Eio.Fiber.fork ~sw (fun () -> send_data_fiber ());
  Eio.Fiber.fork ~sw (fun () -> send_empty_query_fiber ());
  CstructStream.to_flow client_inc client_out
