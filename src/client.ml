type dns_handler = Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit

let udp_listen log sock handle_dns =
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    (* convert Eio.Net.Sockaddr.datagram to Eio.Net.Sockaddr.t *)
    let addr = match addr with `Udp a -> `Udp a in
    log Dns_log.Rx addr trimmedBuf;
    handle_dns `Udp addr trimmedBuf
  done

let create_query identifier record_type authority =
  let question =
    let message = "hello" in
    Eio.traceln "%s" message;
    let data = Base64.encode_exn message in
    assert (String.length data + String.length authority < 255);
    let rec segment_string string =
      let max_len = 63 in
      let len = String.length string in
      if len > max_len then
        let segment = String.sub string 0 max_len in
        let string = String.sub string max_len (len - max_len) in
        let list = segment_string string in
        segment :: list
      else [ string ]
    in
    (* Eio.traceln "%s" data; *)
    let data_name = Array.of_list @@ segment_string data in
    let root = Domain_name.(of_string_exn authority |> host_exn |> to_array) in
    let name_array = Array.append root data_name in
    let hostname = Domain_name.of_array name_array in
    Eio.traceln "%s" @@ Domain_name.to_string hostname;
    Dns.Packet.Question.create hostname record_type
  and header =
    let flags = Dns.Packet.Flags.singleton `Recursion_desired in
    (identifier, flags)
  in
  let query = Dns.Packet.create header question `Query in
  let cs, _ = Dns.Packet.encode `Udp query in
  cs

let make_query sock identifier record_type hostname addr data_subdomain =
  let query =
    create_query identifier record_type (data_subdomain ^ "." ^ hostname)
  in
  Eio.Net.send sock addr query

let start sock log (handle_dns : dns_handler) = udp_listen log sock handle_dns
