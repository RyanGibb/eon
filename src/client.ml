let udp_listen log sock handle_dns =
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    (* convert Eio.Net.Sockaddr.datagram to Eio.Net.Sockaddr.t *)
    let addr = match addr with `Udp a -> `Udp a in
    log Dns_log.Rx addr trimmedBuf;
    handle_dns trimmedBuf
  done

let create_query ~rng record_type authority =
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
    (Randomconv.int16 rng, flags)
  in
  let query = Dns.Packet.create header question `Query in
  let cs, _ = Dns.Packet.encode `Udp query in
  cs

let run hostname nameserver data_subdomain =
  Eio_main.run @@ fun env ->
  let (* TODO support different queruies, or probing access *)
      record_type =
    Dns.Rr_map.Cname
  and (* TODO query ns *)
      addr =
    (* TODO replace this with OCaml call? *)
    match Eio.Net.getaddrinfo_datagram env#net ~service:"domain" nameserver with
    (* just takes first returned value, which is probably ipv6
       TODO add `-4`/`-6` flag *)
    | ipaddr :: _ ->
        Eio.Net.Sockaddr.pp Format.std_formatter ipaddr;
        ipaddr
    | _ -> exit 1
  in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact (Eio.Stdenv.secure_random env) buf;
    buf
  in
  Eio.Switch.run @@ fun sw ->
  let sock =
    let proto =
      match addr with
      | `Udp (ipaddr, _p) ->
          Eio.Net.Ipaddr.fold
            ~v4:(fun _v4 -> `UdpV4)
            ~v6:(fun _v6 -> `UdpV6)
            ipaddr
    in
    Eio.Net.datagram_socket ~sw env#net proto
  in
  let log = Dns_log.log_level_0 Format.std_formatter in
  Eio.Fiber.both
    (fun () ->
      udp_listen log sock (fun buf ->
          match Dns.Packet.decode buf with
          | Ok packet -> (
              match packet.data with
              | `Answer (answer, _authority) -> (
                  match Domain_name.Map.bindings answer with
                  | [ (_key, relevant_map) ] -> (
                      match Dns.Rr_map.find record_type relevant_map with
                      | None -> ()
                      | Some (_ttl, cname) -> (
                          Eio.traceln "%s" @@ Domain_name.to_string cname;
                          match
                            Transport.message_of_domain_name data_subdomain
                              cname
                          with
                          | None -> exit 1
                          | Some (message, _root) ->
                              Eio.traceln "%s" message;
                              exit 0))
                  | _ -> ())
              | _ -> ())
          | _ -> ()))
    (fun () ->
      let query =
        create_query ~rng record_type (data_subdomain ^ "." ^ hostname)
      in
      Eio.Net.send sock addr query)

let cmd =
  let hostname =
    Cmdliner.Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"HOSTNAME" ~doc:"Hostname")
  in
  let nameserver =
    Cmdliner.Arg.(
      required
      & pos 1 (some string) None
      & info [] ~docv:"NAMESERVER" ~doc:"Nameserver.")
  in
  let data_subdomain =
    Cmdliner.Arg.(
      value & opt string "rpc"
      & info [ "d"; "data-subdomain" ] ~docv:"DATA_SUBDOMAIN"
          ~doc:"Data subdomain.")
  in
  let dns_t =
    Cmdliner.Term.(const run $ hostname $ nameserver $ data_subdomain)
  in
  let info = Cmdliner.Cmd.info "client" in
  Cmdliner.Cmd.v info dns_t

let () =
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
