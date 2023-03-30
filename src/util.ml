
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
