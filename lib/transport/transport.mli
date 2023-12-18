val dns_server_stream :
  sw:Eio.Switch.t ->
  net:_ Eio.Net.t ->
  clock:_ Eio.Time.clock ->
  mono_clock:_ Eio.Time.Mono.t ->
  proto:[`Tcp | `Udp ] list ->
  string ->
  Dns_server.Primary.s ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  Eio.Flow.two_way_ty Eio.Resource.t

val dns_client_stream :
  sw:Eio.Switch.t ->
  net:_ Eio.Net.t ->
  clock:_ Eio.Time.clock ->
  random:_ Eio.Flow.source ->
  string ->
  string ->
  string ->
  int ->
  Dns_log.formattedLog ->
  Eio.Flow.two_way_ty Eio.Resource.t

class virtual dns_datagram :
  object
    method virtual send : Cstruct.t -> unit
    method virtual recv : Cstruct.t -> int
  end

val dns_server_datagram :
  sw:Eio.Switch.t ->
  net:_ Eio.Net.t ->
  clock:_ Eio.Time.clock ->
  mono_clock:_ Eio.Time.Mono.t ->
  proto:[`Tcp | `Udp ] list ->
  string ->
  string ->
  Dns_server.Primary.s ref ->
  Dns_log.formattedLog ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  < dns_datagram >

val dns_client_datagram :
  sw:Eio.Switch.t ->
  net:_ Eio.Net.t ->
  clock:_ Eio.Time.clock ->
  random:_ Eio.Flow.source ->
  string ->
  string ->
  string ->
  int ->
  Dns_log.formattedLog ->
  < dns_datagram >

(* TODO docs *)
