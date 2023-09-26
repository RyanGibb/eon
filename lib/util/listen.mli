val on_addresses :
  net:#Eio.Net.t ->
  udp:bool ->
  tcp:bool ->
  (< Eio.Net.datagram_socket ; Eio.Flow.close > -> unit) ->
  (Eio.Net.listening_socket -> unit) ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
