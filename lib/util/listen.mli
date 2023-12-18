(* TODO types... *)
val on_addrs :
  net:[> ([> `Generic] as 'a) Eio.Net.ty] Eio.Resource.t ->
  proto:[< `Tcp | `Udp ] list ->
  ([ `Close | `Datagram | `Platform of [> `Generic ] as 'a  | `Shutdown | `Socket ] Eio.Resource.t -> unit) ->
  ([ `Accept | `Close | `Platform of [> `Generic ] as 'a  | `Socket ] Eio.Resource.t -> unit) ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
