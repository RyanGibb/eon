exception Ignore of unit

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
(** [start ~net ~secure_random ~clock ~mono_clock ~trie ~keys ~log ~addresses ~tcp ~udp ~tcp ~callback]
    start starts a nameserver serving [zonefiles], logging DNS packets with [log],
    binding on the socket addresses formed by the IP address port pairs specified
    in [addresses] for [tcp] and [udp] if true, using [callback] to optionally
    respond modify a response. *)
