module Datagram_server : sig
  val run :
    sw:Eio.Switch.t ->
    < net : _ Eio.Net.t ; clock : _ Eio.Time.clock ; mono_clock : _ Eio.Time.Mono.t ; .. > ->
    [ `Tcp | `Udp ] list ->
    (* TODO add names *)
    string ->
    (* subdomain *)
    string ->
    (* authority *)
    Dns_server.Primary.s ref ->
    Dns_log.formattedLog ->
    (Eio.Net.Ipaddr.v4v6 * int) list ->
    Datagram.t
end

module Datagram_client : sig
  val run :
    sw:Eio.Switch.t ->
    < net : _ Eio.Net.t ; clock : _ Eio.Time.clock ; secure_random : _ Eio.Flow.source ; .. > ->
    string ->
    string ->
    string ->
    int ->
    Dns_log.formattedLog ->
    float ->
    Datagram.t
end

module Stream_server : sig
  val run :
    sw:Eio.Switch.t ->
    < net : _ Eio.Net.t ; clock : _ Eio.Time.clock ; mono_clock : _ Eio.Time.Mono.t ; .. > ->
    [ `Tcp | `Udp ] list ->
    string ->
    Dns_server.Primary.s ref ->
    Dns_log.formattedLog ->
    (Eio.Net.Ipaddr.v4v6 * int) list ->
    Eio.Flow.two_way_ty Eio.Resource.t
end

module Stream_client : sig
  val run :
    sw:Eio.Switch.t ->
    < net : _ Eio.Net.t ; clock : _ Eio.Time.clock ; secure_random : _ Eio.Flow.source ; .. > ->
    string ->
    string ->
    string ->
    int ->
    Dns_log.formattedLog ->
    float ->
    Eio.Flow.two_way_ty Eio.Resource.t
end
