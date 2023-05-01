val start :
  net:#Eio.Net.t ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  ?tcp:bool ->
  ?udp:bool ->
  ?packet_callback:Dns_server.packet_callback ->
  Dns_server.Primary.s ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
