
(* https://www.rfc-editor.org/rfc/rfc1035#section-4 *)

module Header = struct

  type t = {
    id : Cstruct.uint8 ;
    query : Cstruct.uint8 ;
    opcode : Cstruct.uint8 ;
    authorative_answer : bool ;
    truncation : bool ;
    recursion_desired : bool ;
    recursion_available : bool ;
    rcode : Cstruct.uint8 ;
    q_count : Cstruct.uint16 ;
    an_count : Cstruct.uint16 ;
    au_count : Cstruct.uint16 ;
    ad_count : Cstruct.uint16 ;
  }

  let decode buf =
    let id = Cstruct.BE.get_uint16 buf 0 in
    let flags = Cstruct.get_uint8 buf 2 in
    let
      query = flags lsr 7 and
      opcode = (flags land 0x7800) lsr 3 and
      authorative_answer = flags land 5 > 0 and
      truncation = flags land 6 > 0 and
      recursion_desired = flags land 7 > 0 and
      recursion_available = flags land 8 > 0 and
      rcode = (Cstruct.get_uint8 buf 3) land 0x0F
    in
    let
      q_count = Cstruct.BE.get_uint16 buf 4 and
      an_count = Cstruct.BE.get_uint16 buf 6 and
      au_count = Cstruct.BE.get_uint16 buf 8 and
      ad_count = Cstruct.BE.get_uint16 buf 10
    in
    { id ; query ; opcode ;
      authorative_answer ; truncation ; recursion_desired ; recursion_available ; rcode ;
      q_count ; an_count ; au_count ; ad_count ; }

end

module Query = struct
  type t = {
    header : Header.t ;
    domain : string List.t ;
    qtype : Cstruct.uint16 ;
    qclass : Cstruct.uint16 ;
  }

  let decode_query buf =
    let header = Header.decode buf in
    if header.q_count != 1 then Error (`Msg ("query count not 1")) else
    let rec decode_name buf =
      let len = Cstruct.get_uint8 buf 0 in
      if len > 0 then
        let label, buf = Cstruct.split ~start:1 buf len in
        let label = Cstruct.to_string label in
        let domain, off = decode_name buf in
        (label :: domain), off
      else [], buf.off + 1
    in
    let domain, off = decode_name (Cstruct.sub buf 12 (buf.len - 12)) in
    let qtype = Cstruct.BE.get_uint16 buf off
    and qclass = Cstruct.BE.get_uint16 buf (off + 2) in
    Ok { header ; domain ; qtype ; qclass ; }

end

let handle_client sock _stdout =
  let b = Cstruct.create 512 in
  while true do
    let addr, size = Eio.Net.recv sock b in
    let recv, _ = Cstruct.split b size in
    Eio.traceln "received:"; Cstruct.hexdump recv;
    match Query.decode_query recv with
    | Error (`Msg e) -> Eio.traceln "%s" e
    | Ok query ->
      Eio.traceln "Client: received id %d query %d opcode %d authorative_answer %b truncation %b recursion_desired %b recursion_available %b rcode %d q_count %d an_count %d au_count %d ad_count %d domain '%s' type %d qclass %d" query.header.id query.header.query query.header.opcode query.header.authorative_answer query.header.truncation query.header.recursion_desired query.header.recursion_available query.header.rcode query.header.q_count query.header.an_count query.header.au_count query.header.ad_count (String.concat "." query.domain) query.qtype query.qclass;
      Eio.Net.send sock addr recv
  done

let main ~net ~stdout =
  Eio.Switch.run @@ fun sw ->
  let get_sock addr = Eio.Net.datagram_socket ~sw net (`Udp (addr, 53)) in
  Eio.Fiber.both
    (fun () -> handle_client (get_sock Eio.Net.Ipaddr.V6.loopback) stdout)
    (fun () -> handle_client (get_sock Eio.Net.Ipaddr.V4.loopback) stdout)

let () = Eio_main.run @@ fun env ->
  main ~net:(Eio.Stdenv.net env) ~stdout:(Eio.Stdenv.stdout env)
