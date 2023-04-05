let message_of_domain_name sudbomain name =
  match Domain_name.find_label name (fun s -> String.equal sudbomain s) with
  | None -> None
  | Some i ->
      let data_name =
        Domain_name.drop_label_exn ~rev:true
          ~amount:(Domain_name.count_labels name - i)
          name
      in
      let root = Domain_name.drop_label_exn ~amount:i name in
      let data_array = Domain_name.to_array data_name in
      let data = String.concat "" (Array.to_list data_array) in
      let message = Base64.decode_exn data in
      Some (message, root)

let domain_name_of_message root message =
  let data = Base64.encode_exn message in
  let authority = Domain_name.to_string root in
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
  let data_name = Array.of_list @@ segment_string data in
  let name_array = Array.append (Domain_name.to_array root) data_name in
  let hostname = Domain_name.of_array name_array in
  hostname

let callback ~data_subdomain _trie question =
  let name, qtype = question in
  match message_of_domain_name data_subdomain name with
  | None -> None
  | Some (message, root) -> (
      Eio.traceln "%s" message;

      let reply =
        let rev x =
          let len = String.length x in
          String.init len (fun n -> String.get x (len - n - 1))
        in
        rev message
      in

      let hostname = domain_name_of_message root reply in

      let flags = Dns.Packet.Flags.singleton `Authoritative in
      match qtype with
      | `K (Dns.Rr_map.K Dns.Rr_map.Cname) ->
          let rr = Dns.Rr_map.singleton Dns.Rr_map.Cname (1l, hostname) in
          let answer = Domain_name.Map.singleton name rr in
          let authority = Dns.Name_rr_map.empty in
          (* Name_rr_map.remove_sub (Name_rr_map.singleton au Ns (ttl, ns)) answer *)
          let data = (answer, authority) in
          let additional = None in
          Some (flags, data, additional)
      (* TODO support more RRs ? *)
      | _ ->
          Eio.traceln "unsupported RR";
          None (* TODO proper logging *))
