type dns_handler =
  Dns.proto ->
  Eio.Net.Sockaddr.t ->
  Cstruct.t ->
  (* answers *)
  (Dns.proto * Ipaddr.t * int * Cstruct.t) list
  (* queries *)
  * (Dns.proto * Ipaddr.t * Cstruct.t) list

val resolver :
  net:#Eio.Net.t ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  ?tcp:bool ->
  ?udp:bool ->
  Dns_resolver.t ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
