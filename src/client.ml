

let udp_listen log sock handle_dns =
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    let addr = Util.sockaddr_of_sockaddr_datagram addr in
    log Dns_log.Rx addr trimmedBuf;
    handle_dns trimmedBuf
  done

let create_query ~rng record_type authority =
  let
    question =
      let message = "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohhellohellohellohellohellohellohellohellohellohellohellohellohellohellohello" in
      let data = Base64.encode_exn message in
      assert (String.length data + String.length authority < 255);
      let rec segment_string list string =
        let max_len = 63 in
        let len = String.length string in
        if len > max_len then
          let segment = String.sub string 0 max_len  in
          let string = String.sub string max_len (len - max_len) in
          segment_string (segment :: list) string
        else
          string :: list
      in
      let data_name = Array.of_list @@ segment_string [] data in
      let root = Domain_name.(of_string_exn authority |> host_exn |> to_array) in
      let name_array = Array.append root data_name in
      let hostname = Domain_name.of_array name_array in
      Dns.Packet.Question.create hostname record_type and
    header =
      let flags = Dns.Packet.Flags.singleton `Recursion_desired in
      Randomconv.int16 rng, flags
  in
  let query = Dns.Packet.create header question `Query in
  let cs, _ = Dns.Packet.encode `Udp query in
  cs

let run hostname nameserver = Eio_main.run @@ fun env ->
  let
    record_type = Dns.Rr_map.A and
    (* TODO query ns *)
    addr = `Udp (Ipaddr.of_string_exn nameserver |> Util.convert_ipaddr_to_eio, 53)
  in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact (Eio.Stdenv.secure_random env) buf;
    buf
  in
  Eio.Switch.run @@ fun sw -> 
  let sock = Eio.Net.datagram_socket ~sw env#net `UdpV4 in
  let log = Dns_log.log_level_0 Format.std_formatter in
  Eio.Fiber.both
    (fun () ->
      udp_listen log sock (fun buf ->
        match Dns.Packet.decode buf with
        | Ok packet ->
          (match packet.data with
          | `Answer (answer, _authority) ->
            (match Domain_name.Map.bindings answer with
            | [ _key, relevant_map ] ->
              (match Dns.Rr_map.find record_type relevant_map with
              | None -> ()
              | Some (_ttl, answer) ->
                (match Ipaddr.V4.Set.choose_opt answer with
                  | None -> ()
                  | Some ip -> Eio.traceln "%s" @@ Ipaddr.V4.to_string ip; exit 0
                )
              )
              | _ -> ()
            )
          | _ -> ()
          )
        | _ -> ()
      )
    )
    (fun () ->
      let query = create_query ~rng record_type hostname in
      Eio.Net.send sock addr query;
    )

let cmd =
  let hostname =
    Cmdliner.Arg.(required & pos 0 (some string) None & info [] ~docv:"HOSTNAME" ~doc:"Hostname")
  in
  let nameserver =
    Cmdliner.Arg.(required & pos 1 (some string) None & info [] ~docv:"NAMESERVER" ~doc:"Nameserver.")
  in
  let dns_t = Cmdliner.Term.(const run $ hostname $ nameserver) in
  let info = Cmdliner.Cmd.info "client" in
  Cmdliner.Cmd.v info dns_t

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Error);
  exit (Cmdliner.Cmd.eval cmd)
