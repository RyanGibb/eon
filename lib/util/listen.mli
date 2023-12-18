val on_addrs :
  net:[> 'a Eio.Net.ty ] Eio.Resource.t ->
  proto:[< `Tcp | `Udp ] list ->
  ('a Eio.Net.datagram_socket_ty Eio.Resource.t -> unit) ->
  ('a Eio.Net.listening_socket_ty Eio.Resource.t -> unit) ->
  (Eio.Net.Ipaddr.v4v6 * int) list -> unit
