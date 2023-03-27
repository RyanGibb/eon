
let message_of_domain_name sudbomain name =
  match Domain_name.find_label name (fun s -> String.equal sudbomain s) with
  | None -> None
  | Some i ->
    let data_name = Domain_name.drop_label_exn ~rev:true ~amount:(Domain_name.count_labels name - i) name in
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
      let segment = String.sub string 0 max_len  in
      let string = String.sub string max_len (len - max_len) in
      let list = segment_string string in
      segment :: list
    else
      [ string ]
  in
  let data_name = Array.of_list @@ segment_string data in
  let name_array = Array.append (Domain_name.to_array root) data_name in
  let hostname = Domain_name.of_array name_array in
  hostname
    
let convert_ipaddr_to_eio (addr : Ipaddr.t) =
  (match addr with
  | Ipaddr.V4 v4 -> Ipaddr.V4.to_octets v4
  | Ipaddr.V6 v6 -> Ipaddr.V6.to_octets v6
  ) |> Eio.Net.Ipaddr.of_raw

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
