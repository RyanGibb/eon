
let listen ~clock ~mono_clock sock server =
  let buf = Cstruct.create 512 in
  while true do
    let addr, _size = Eio.Net.recv sock buf in
    let src, port = match addr with
      | `Udp (ip, p) -> 
        let src = (ip :> string) in
        let src = Eio.Net.Ipaddr.fold
          ~v4:(fun _v4 -> Ipaddr.V4 (Result.get_ok @@ Ipaddr.V4.of_octets src))
          ~v6:(fun _v6 -> Ipaddr.V6 (Result.get_ok @@ Ipaddr.V6.of_octets src))
          ip
        in
        src, p
    in
    let now = Ptime.of_float_s @@ Eio.Time.now clock in
    match now with
    | None -> ()
    | Some now ->
      let ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now mono_clock in
      (* todo handle these *)
      let _t, answers, _notify, _n, _key =
        Dns_server.Primary.handle_buf !server now ts `Udp src port buf
      in
      List.iter (Eio.Net.send sock addr) answers
  done

let main ~net ~random ~clock ~mono_clock zonefile =
  Eio.Switch.run @@ fun sw ->
  let get_sock addr = Eio.Net.datagram_socket ~sw net (`Udp (addr, 53)) in
  let _zones, trie = Dns_zone.decode_zones [ ("freumh.org", zonefile) ] in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact random buf;
    buf
  in
  let server = ref @@ Dns_server.Primary.create ~rng trie in
  listen ~clock ~mono_clock (get_sock Eio.Net.Ipaddr.V6.any) server

let () = Eio_main.run @@ fun env ->
  let zonefile =
    let ( / ) = Eio.Path.( / ) in
    Eio.Path.load ((Eio.Stdenv.fs env) / Sys.argv.(1)) in
  main
    ~net:(Eio.Stdenv.net env)
    ~random:(Eio.Stdenv.secure_random env)
    ~clock:(Eio.Stdenv.clock env)
    ~mono_clock:(Eio.Stdenv.mono_clock env)
    zonefile
