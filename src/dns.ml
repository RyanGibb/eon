
(* https://www.rfc-editor.org/rfc/rfc1035#section-4 *)

module Packet = struct  

  let decode buf =
    (* TODO bounds checking *)
    let id = Cstruct.BE.get_uint16 buf 0 in
    let flags = Cstruct.get_uint8 buf 2 in
      let query = flags lsr 7 in
      let opcode = (flags land 0x7800) lsr 3 in
      let authorative_answer = flags land 5 > 0 in
      let truncation = flags land 6 > 0 in
      let recursion_desired = flags land 7 > 0 in
      let recursion_available = flags land 8 > 0 in
    let rcode = (Cstruct.get_uint8 buf 3) land 0x0F in
    let
      q_count = Cstruct.BE.get_uint16 buf 4 and
      an_count = Cstruct.BE.get_uint16 buf 6 and
      au_count = Cstruct.BE.get_uint16 buf 8 and
      ad_count = Cstruct.BE.get_uint16 buf 10
    in
    let rec decode_name buf =
      let len = Cstruct.get_uint8 buf 0 in
      if len > 0 then
        let label, buf = Cstruct.split ~start:1 buf len in
        let label = Cstruct.to_string label in
        let names, off = decode_name buf in
        (label :: names), off
      else [], buf.off + 1
    in
    let names, off = decode_name (Cstruct.sub buf 12 (buf.len - 12)) in
    let name = String.concat "." names in
    let typ = Cstruct.BE.get_uint16 buf off
    and cls = Cstruct.BE.get_uint16 buf (off + 2) in
    id, query, opcode, authorative_answer, truncation, recursion_desired, recursion_available, rcode, q_count, an_count, au_count, ad_count, name, typ, cls

end

let handle_client sock _stdout =
  let b = Cstruct.create 512 in
  while true do
    let addr, size = Eio.Net.recv sock b in
    let recv, _ = Cstruct.split b size in
    Eio.traceln "received:"; Cstruct.hexdump recv;
    let id, query, opcode, authorative_answer, truncation, recursion_desired, recursion_available, rcode, q_count, an_count, au_count, ad_count, name, typ, cls = Packet.decode recv in
    Eio.traceln "Client: received id %d query %d opcode %d authorative_answer %b truncation %b recursion_desired %b recursion_available %b rcode %d q_count %d an_count %d au_count %d ad_count %d name '%s' type %d class %d" id query opcode authorative_answer truncation recursion_desired recursion_available rcode q_count an_count au_count ad_count name typ cls;
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
