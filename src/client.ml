
let convert_ipaddr_to_eio (addr : Ipaddr.t) =
  (match addr with
  | Ipaddr.V4 v4 -> Ipaddr.V4.to_octets v4
  | Ipaddr.V6 v6 -> Ipaddr.V6.to_octets v6
  ) |> Eio.Net.Ipaddr.of_raw

let send_recv ~mono sock ns tx =
  try
    Eio.Time.Timeout.run_exn (Eio.Time.Timeout.v mono @@ Mtime.Span.of_uint64_ns 5000000000L) (fun () ->
    Eio.Net.send sock ns tx;
    (* we assume in order deliver *)
    let buf = Cstruct.create 100000 in
    (* todo check *)
    ignore @@ Eio.Net.recv sock buf;
    Ok buf
  )
  with Eio.Time.Timeout -> Error (`Msg "DNS request timeout")

let get_resource_record ~mono ~rng query_type name sock addr =
  let tx, state = Dns_client.Pure.make_query rng `Udp `Auto name query_type in
  match send_recv ~mono sock addr tx with
  | Error _ ->
    (* TODO log *)
    Error ()
  | Ok buf -> match Dns_client.Pure.handle_response state buf with
    | Ok `Data x ->
      Ok x
    | Ok ((`No_data _ | `No_domain _) as _nodom) ->
      Error ()
    | Error `Msg _ -> Error ()
    | Ok `Partial -> Error ()

let run domainName nameserver = Eio_main.run @@ fun env ->
  let
    record = Dns.Rr_map.A and
    name = Domain_name.(host_exn (of_string_exn domainName)) and
    addr = `Udp (Ipaddr.of_string_exn nameserver |> convert_ipaddr_to_eio, 53)
  in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact (Eio.Stdenv.secure_random env) buf;
    buf
  in
  Eio.Switch.run @@ fun sw -> 
  let sock = Eio.Net.datagram_socket ~sw env#net `UdpV4 in
  match get_resource_record ~mono:env#mono_clock ~rng record name sock addr with
  | Error _ -> ()
  | Ok (_ttl, res) -> match Ipaddr.V4.Set.choose_opt res with
    | None -> ()
    | Some ip -> Eio.traceln "%s" @@ Ipaddr.V4.to_string ip

let cmd =
  let domainName =
    Cmdliner.Arg.(required & pos 0 (some string) None & info [] ~docv:"DOMAN_NAME" ~doc:"Domain name")
  in
  let nameserver =
    Cmdliner.Arg.(required & pos 1 (some string) None & info [] ~docv:"NAMESERVER" ~doc:"Nameserver.")
  in
  let dns_t = Cmdliner.Term.(const run $ domainName $ nameserver) in
  let info = Cmdliner.Cmd.info "dip" in
  Cmdliner.Cmd.v info dns_t

let () =
  (* TODO make this configurable *)
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Error);
  exit (Cmdliner.Cmd.eval cmd)
