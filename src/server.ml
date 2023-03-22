
type handle_dns = Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list

let dns_handler ~server ~clock ~mono_clock = fun proto addr buf ->
  (* TODO handle notify, n, and key *)
  let new_server, answers, _notify, _n, _key =
    (* TODO modify ocaml-dns not to require this? *)
    let now = Ptime.of_float_s @@ Eio.Time.now clock |> Option.get in
    let ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now mono_clock in
    let src, port = Util.convert_eio_to_ipaddr addr in
    Dns_server.Primary.handle_buf !server now ts proto src port buf
  in
  (* TODO is this thread safe? *)
  server := new_server;
  answers

let udp_listen log handle_dns sock =
  (* Support queries of up to 4kB.
     The 512B limit described in rfc1035 section 2.3.4 is outdated) *)
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    let addr = Util.sockaddr_of_sockaddr_datagram addr in
    log Dns_log.Rx addr trimmedBuf;
    let answers = handle_dns `Udp addr trimmedBuf in
    List.iter (fun b -> log Dns_log.Tx addr b; Eio.Net.send sock addr b) answers
  done

type connection_handler = Eio.Net.stream_socket -> Eio.Net.Sockaddr.stream -> unit

  let tcp_handle log handle_dns =
    let connection_handler sock addr =
      (* Persist connection until EOF, rfc7766 section 6.2.1 *)
      try
        while true do
          (* Messages sent over TCP have a 2 byte prefix giving the message length, rfc1035 section 4.2.2 *)
        let prefix = Cstruct.create 2 in
        Eio.Flow.read_exact sock prefix;
        let len = Cstruct.BE.get_uint16 prefix 0 in
        let buf = Cstruct.create len in
        Eio.Flow.read_exact sock buf;
        let addr = Util.sockaddr_of_sockaddr_stream addr in
        log Dns_log.Rx addr buf;
        let answers = handle_dns `Tcp addr buf in
        List.iter (fun b ->
          log Dns_log.Tx addr b;
          (* add prefix, described in rfc1035 section 4.2.2 *)
          let prefix = Cstruct.create 2 in
          Cstruct.BE.set_uint16 prefix 0 b.len;
          Eio.Flow.write sock [ prefix ; b ]
        ) answers
        done
      (* ignore EOF *)
      with End_of_file -> ()
  in connection_handler

let tcp_listen listeningSock connection_handler =
  while true do
    let on_error = Eio.traceln "Error handling connection: %a" Fmt.exn in
    Eio.Switch.run @@ fun sw ->
      Eio.Net.accept_fork ~sw listeningSock ~on_error connection_handler
  done
