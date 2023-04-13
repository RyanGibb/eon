(* rfc1035 section 2.3.4 *)
(* TODO is this wrong? *)
let max_name_len = 200 (* should be 255 *)
let max_label_len = 63

(* as base64 encodes 6 bits in a byte, this gives us 3/4 of the `max_name_len` rounded up  *)
let max_encoded_len = 1 + ((max_name_len - 1) / 4 * 3)

let message_of_domain_name sudbomain name =
  match Domain_name.find_label name (fun s -> String.equal sudbomain s) with
  | None -> None
  | Some i -> (
      let data_name =
        Domain_name.drop_label_exn ~rev:true
          ~amount:(Domain_name.count_labels name - i)
          name
      in
      let root = Domain_name.drop_label_exn ~amount:i name in
      let data_array = Domain_name.to_array data_name in
      let data = String.concat "" (Array.to_list data_array) in
      if String.length data == 0 then None
      else
        try
          let message = Base64.decode_exn data in
          Some (message, root)
        with Invalid_argument e ->
          Format.fprintf Format.err_formatter "Transport: error decoding %s\n" e;
          Format.pp_print_flush Format.err_formatter ();
          None)

let domain_name_of_message root message =
  let data = Base64.encode_exn message in
  let authority = Domain_name.to_string root in
  assert (String.length data + String.length authority < max_name_len);
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
  hostname

let get_callback ~data_subdomain ~inqueue ~outqueue : Dns_server.callback =
 fun _trie question ->
  let name, qtype = question in
  match message_of_domain_name data_subdomain name with
  | None -> None
  | Some (message, root) -> (
      (* TODO synchronisation *)
      if String.length message > 0 then
        inqueue := Cstruct.of_string message :: !inqueue;

      let buf =
        let rootLen = String.length (Domain_name.to_string root) in
        Cstruct.create (max_encoded_len - rootLen)
      in

      (* TODO synchronisation *)
      while Cstruct.lenv !outqueue == 0 do
        Eio.Fiber.yield ()
      done;
      let read, newOutqueue = Cstruct.fillv ~src:!outqueue ~dst:buf in
      outqueue := newOutqueue;

      (* let buf = Cstruct.sub buf 0 read in *)
      let reply = Cstruct.to_string buf in
      let hostname = domain_name_of_message root reply in
      let flags = Dns.Packet.Flags.singleton `Authoritative in
      match qtype with
      | `K (Dns.Rr_map.K Dns.Rr_map.Cname) ->
          let rr = Dns.Rr_map.singleton Dns.Rr_map.Cname (1l, hostname) in
          let answer = Domain_name.Map.singleton name rr in
          let authority = Dns.Name_rr_map.empty in
          let data = (answer, authority) in
          let additional = None in
          Some (flags, data, additional)
      | `Axfr | `Ixfr ->
          Format.fprintf Format.err_formatter
            "Transport: unsupported operation zonetransfer";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `Any ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR ANY";
          Format.pp_print_flush Format.err_formatter ();
          None
      | `K rr ->
          Format.fprintf Format.err_formatter "Transport: unsupported RR %a"
            Dns.Rr_map.ppk rr;
          Format.pp_print_flush Format.err_formatter ();
          None)

class virtual dns_flow =
  object
    inherit Eio.Flow.two_way
  end

let dns_server ~sw ~net ~clock ~mono_clock ~tcp ~udp data_subdomain server log
    addresses =
  let inqueue = ref [] and outqueue = ref [] in

  Eio.Fiber.fork ~sw (fun () ->
      Server.start ~net ~clock ~mono_clock ~tcp ~udp
        ~callback:(get_callback ~data_subdomain ~inqueue ~outqueue)
        server log addresses);
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

    method write bufs =
      (* TODO synchronisation *)
      outqueue := List.append !outqueue bufs

    method read_methods = []

    method read_into buf =
      (* TODO synchronisation *)
      while Cstruct.lenv !inqueue == 0 do
        Eio.Fiber.yield ()
      done;
      let read, newInqueue = Cstruct.fillv ~src:!inqueue ~dst:buf in
      inqueue := newInqueue;
      read

    method shutdown _cmd = ()
  end

let dns_client ~sw ~net nameserver data_subdomain authority port log =
  let inqueue = ref [] and outqueue = ref [] in

  (* TODO support different queruies, or probing access *)
  let record_type = Dns.Rr_map.Cname
  and addr =
    match
      Eio.Net.getaddrinfo_datagram net ~service:(Int.to_string port) nameserver
    with
    (* just takes first returned value, which is probably ipv6 *)
    | ipaddr :: _ ->
        Eio.Net.Sockaddr.pp Format.std_formatter ipaddr;
        ipaddr
    | _ ->
        Format.fprintf Format.err_formatter "Invalid address: %s" nameserver;
        Format.pp_print_flush Format.err_formatter ();
        exit 1
  in
  let handle_dns _proto _addr buf : unit =
    let ( let* ) o f = match o with None -> () | Some v -> f v in
    let* packet =
      match Dns.Packet.decode buf with
      | Ok packet -> Some packet
      | Error err ->
          Format.fprintf Format.err_formatter "Transport: error decoding %a"
            Dns.Packet.pp_err err;
          Format.pp_print_flush Format.err_formatter ();
          None
    in
    let* answer =
      match packet.data with
      | `Answer (answer, _authority) -> Some answer
      | _ ->
          Format.fprintf Format.err_formatter "Transport: no answer section";
          Format.pp_print_flush Format.err_formatter ();
          None
    in
    let* map =
      match Domain_name.Map.bindings answer with
      | [ (_key, map) ] -> Some map
      | _ ->
          Format.fprintf Format.err_formatter "Transport: no answer";
          Format.pp_print_flush Format.err_formatter ();
          None
    in
    let* _ttl, cname = Dns.Rr_map.find record_type map in
    match message_of_domain_name data_subdomain cname with
    | None -> exit 1
    | Some (message, _root) ->
        (* TODO synchronisation *)
        if String.length message > 0 then
          inqueue := Cstruct.of_string message :: !inqueue;
        ()
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
  let send_fiber () =
    let buf =
      (* String.length (data_subdomain ^ "." ^ authority) *)
      let rootLen =
        String.length data_subdomain + 1 + String.length authority
      in
      Cstruct.create (max_encoded_len - rootLen)
    in
    while true do
      (* TODO better timing *)
      while Cstruct.lenv !outqueue == 0 do
        Eio.Fiber.yield ()
      done;

      (* TODO synchronisation *)
      let read, newOutqueue = Cstruct.fillv ~src:!outqueue ~dst:buf in
      outqueue := newOutqueue;

      (* let buf = Cstruct.sub buf 0 read in *)
      let reply = Cstruct.to_string buf in
      let hostname =
        let root = Domain_name.of_array [| authority; data_subdomain |] in
        domain_name_of_message root reply
      in
      Client.send_query log 0 record_type hostname sock addr
    done
  in
  Eio.Fiber.fork ~sw (fun () -> Client.listen sock log handle_dns);
  Eio.Fiber.fork ~sw (fun () -> send_fiber ());

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

    method write bufs = outqueue := List.append !outqueue bufs
    method read_methods = []

    method read_into buf =
      (* TODO synchronisation *)
      while Cstruct.lenv !inqueue == 0 do
        Eio.Fiber.yield ()
      done;
      let read, newInqueue = Cstruct.fillv ~src:!inqueue ~dst:buf in
      inqueue := newInqueue;
      read

    method shutdown _cmd = ()
  end
