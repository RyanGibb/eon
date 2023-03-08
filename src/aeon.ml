
(* TODO a Ipaddr.V4.t and Ipaddr.V6.t string representation should simplify this:
  See https://github.com/mirage/ocaml-ipaddr/issues/113 *)
let convert_eio_to_ipaddr (addr : Eio.Net.Sockaddr.t) =
  match addr with
  | `Udp (ip, p) | `Tcp (ip, p) ->
    let src = (ip :> string) in
    let src = Eio.Net.Ipaddr.fold
      ~v4:(fun _v4 -> Ipaddr.V4 (Result.get_ok @@ Ipaddr.V4.of_octets src))
      ~v6:(fun _v6 -> Ipaddr.V6 (Result.get_ok @@ Ipaddr.V6.of_octets src))
      ip
    in
    src, p
  (* TODO better way to display this message? *)
  | `Unix _ -> failwith "Unix sockets not supported";;

(* TODO is there a more elgant way to do this? *)

(* convert Eio.Net.Sockaddr.datagram to Eio.Net.Sockaddr.t *)
let sockaddr_of_sockaddr_datagram (addr : Eio.Net.Sockaddr.datagram) = match addr with
  | `Udp a -> `Udp a

(* convert Eio.Net.Sockaddr.stream to Eio.Net.Sockaddr.t *)
let sockaddr_of_sockaddr_stream (addr : Eio.Net.Sockaddr.stream) = match addr with
  | `Tcp a -> `Tcp a
  | `Unix _ -> failwith "Unix sockets not supported"

let handle_dns proto ~clock ~mono_clock server addr buf =
  (* TODO handle notify, n, and key *)
  let new_server, answers, _notify, _n, _key =
    (* TODO modify ocaml-dns not to require this? *)
    let now = Ptime.of_float_s @@ Eio.Time.now clock |> Option.get in
    let ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now mono_clock in
    let src, port = convert_eio_to_ipaddr addr in
    Dns_server.Primary.handle_buf !server now ts proto src port buf
  in
  (* TODO is this thread safe? *)
  server := new_server;
  answers

let udp_listen ~log ~handle_dns sock server =
  (* Support queries of up to 4kB.
     The 512B limit described in rfc1035 section 2.3.4 is outdated) *)
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    let addr = sockaddr_of_sockaddr_datagram addr in
    log `Rx addr trimmedBuf;
    let answers = handle_dns `Udp server addr trimmedBuf in
    List.iter (fun b -> log `Tx addr b; Eio.Net.send sock addr b) answers
  done

  let tcp_handle ~log ~handle_dns server sock addr =
  (* Persist connection until EOF, rfc7766 section 6.2.1 *)
  try
    while true do
      (* Messages sent over TCP have a 2 byte prefix giving the message length, rfc1035 section 4.2.2 *)
    let prefix = Cstruct.create 2 in
    Eio.Flow.read_exact sock prefix;
    let len = Cstruct.BE.get_uint16 prefix 0 in
    let buf = Cstruct.create len in
    Eio.Flow.read_exact sock buf;
    let addr = sockaddr_of_sockaddr_stream addr in
    log `Rx addr buf;
    let answers = handle_dns `Tcp server addr buf in
    List.iter (fun b ->
      log `Tx addr b;
      (* add prefix, described in rfc1035 section 4.2.2 *)
      let prefix = Cstruct.create 2 in
      Cstruct.BE.set_uint16 prefix 0 b.len;
      Eio.Flow.write sock [ prefix ; b ]
    ) answers
    done
  (* ignore EOF *)
  with End_of_file -> ()

let tcp_listen listeningSock connection_handler =
  while true do
    let on_error = Eio.traceln "Error handling connection: %a" Fmt.exn in
    Eio.Switch.run @@ fun sw ->
      Eio.Net.accept_fork ~sw listeningSock ~on_error connection_handler
  done
  
let run zonefiles log_level = Eio_main.run @@ fun env ->
  let log = (match log_level with
    | 0 -> Aeon_log.log_level_0
    | 1 -> Aeon_log.log_level_1
    | 2 -> Aeon_log.log_level_2
    | 3 -> Aeon_log.log_level_3
    | _ -> if log_level < 0 then Aeon_log.log_level_0 else Aeon_log.log_level_2
  ) Format.std_formatter
  in
  let trie, keys = Aeon_zonefile.parse_zonefiles ~fs:(Eio.Stdenv.fs env) zonefiles in
  (* TODO modify ocaml-dns not to require this? *)
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact (Eio.Stdenv.secure_random env) buf;
    buf
  in
  let server = ref @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign trie in
  (* We listen on in6addr_any to bind to all interfaces. If we also listen on
      INADDR_ANY, this collides with EADDRINUSE. However we can recieve IPv4 traffic
      too via IPv4-mapped IPv6 addresses [0]. It might be useful to look at using
      happy-eyeballs to choose between IPv4 and IPv6, however this may have
      peformance implications [2]. Better might be to explicitly listen per
      interface on IPv4 and/or Ipv6, which would allow the user granular control.
      BSD's also disable IPv4-mapped IPv6 address be default, so this would enable
      better portability.
      [0] https://www.rfc-editor.org/rfc/rfc3493#section-3.7
      [1] https://labs.apnic.net/presentations/store/2015-10-04-dns-dual-stack.pdf *)
  let handle_dns = handle_dns ~clock:(Eio.Stdenv.clock env) ~mono_clock:(Eio.Stdenv.mono_clock env) in
  Eio.Fiber.both
  (fun () ->
    Eio.Switch.run @@ fun sw ->
    let sockUDP =
      try
        (* TODO make port configurable *)
        Eio.Net.datagram_socket ~sw (Eio.Stdenv.net env) (`Udp (Eio.Net.Ipaddr.V6.any, 53))
      with
      (* TODO proper error handling *)
      | Unix.Unix_error (Unix.EADDRINUSE, "bind", _) -> Eio.traceln "error"; failwith "whoops"
    in
    udp_listen ~log ~handle_dns sockUDP server)
  (fun () ->
    Eio.Switch.run @@ fun sw ->
    let sockTCP =
      try
        Eio.Net.listen ~sw ~backlog:4096 (Eio.Stdenv.net env) (`Tcp (Eio.Net.Ipaddr.V6.any, 53))
      with
      | Unix.Unix_error (Unix.EADDRINUSE, "bind", _) -> Eio.traceln "error"; failwith "oops"
    in
    let connection_handler = tcp_handle ~log ~handle_dns server in
    tcp_listen sockTCP connection_handler);;


let cmd =
  (* TODO add port argument *)
  let zonefiles =
    let doc = "Zonefile path." in
    Cmdliner.Arg.(value & opt_all string [] & info ["z"; "zonefile"] ~docv:"ZONEFILE_PATHS" ~doc) in
  (* TODO add descriptions *)
  let logging =
    let doc = "Log level." in
    Cmdliner.Arg.(value & opt int 1 & info ["l"; "log-level"] ~docv:"LOG_LEVEL" ~doc)
  in
  let dns_t = Cmdliner.Term.(const run $ zonefiles $ logging) in
  let info = Cmdliner.Cmd.info "dns" in
  Cmdliner.Cmd.v info dns_t

let () =
  (* TODO make this configurable *)
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Error);
  exit (Cmdliner.Cmd.eval cmd)
