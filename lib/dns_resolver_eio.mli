type dns_handler =
  Dns.proto ->
  Eio.Net.Sockaddr.t ->
  Cstruct.t ->
  (* answers *)
  (Dns.proto * Ipaddr.t * int * Cstruct.t) list
  (* queries *)
  * (Dns.proto * Ipaddr.t * Cstruct.t) list

val resolver :
  net:_ Eio.Net.t ->
  clock:_ Eio.Time.clock ->
  mono_clock:_ Eio.Time.Mono.t ->
  proto:[`Tcp | `Udp ] list ->
  Dns_resolver.t ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
