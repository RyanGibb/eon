
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

let dns_handler ~server ~clock ~mono_clock = fun proto addr buf ->
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

let udp_listen ~log ~handle_dns sock =
  (* Support queries of up to 4kB.
     The 512B limit described in rfc1035 section 2.3.4 is outdated) *)
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    let addr = sockaddr_of_sockaddr_datagram addr in
    log Dns_log.Rx addr trimmedBuf;
    let answers = handle_dns `Udp addr trimmedBuf in
    List.iter (fun b -> log Dns_log.Tx addr b; Eio.Net.send sock addr b) answers
  done

  let tcp_handle ~log ~handle_dns sock addr =
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

let tcp_listen listeningSock connection_handler =
  while true do
    let on_error = Eio.traceln "Error handling connection: %a" Fmt.exn in
    Eio.Switch.run @@ fun sw ->
      Eio.Net.accept_fork ~sw listeningSock ~on_error connection_handler
  done
