val on_addrs :
  net:#Eio.Net.t ->
  proto:[`Tcp | `Udp ] list ->
  (< Eio.Net.datagram_socket ; Eio.Flow.close > -> unit) ->
  (Eio.Net.listening_socket -> unit) ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
