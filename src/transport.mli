class virtual dns_flow :
  object
    inherit Eio.Generic.t
    inherit Eio.Flow.two_way
  end

val dns_server :
  sw:Eio.Switch.t ->
  net:#Eio.Net.t ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  tcp:bool ->
  udp:bool ->
  string ->
  Dns_server.Primary.s ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  < dns_flow >

val dns_client :
  sw:Eio.Switch.t ->
  net:#Eio.Net.t ->
  clock:#Eio.Time.clock ->
  random:#Eio.Flow.source ->
  string ->
  string ->
  string ->
  int ->
  Dns_log.formattedLog ->
  < dns_flow >
