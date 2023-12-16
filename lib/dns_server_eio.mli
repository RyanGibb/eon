(* The plumbing for a process to send and receive DNS packets.
   Takes a `dns_handler` that returns a list of answers *)

type dns_handler =
  Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list

val with_handler :
  net:#Eio.Net.t ->
  proto:[`Tcp | `Udp ] list ->
  dns_handler ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit

val primary :
  net:#Eio.Net.t ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  proto:[`Tcp | `Udp ] list ->
  ?packet_callback:Dns_server.packet_callback ->
  Dns_server.Primary.s ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit

(* TODO support secondary server *)
