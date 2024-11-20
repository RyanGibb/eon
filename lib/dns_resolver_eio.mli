type dns_handler =
  Dns.proto ->
  Eio.Net.Sockaddr.t ->
  string ->
  (* answers *)
  (Dns.proto * Ipaddr.t * int * string) list (* queries *)
  * (Dns.proto * Ipaddr.t * string) list

val resolver :
  < net : _ Eio.Net.t
  ; clock : _ Eio.Time.clock
  ; mono_clock : _ Eio.Time.Mono.t
  ; .. > ->
  [ `Tcp | `Udp ] list ->
  Dns_resolver.t ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
