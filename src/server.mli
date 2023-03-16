
val handle_dns :
  server:Dns_server.Primary.s ref ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list

val udp_listen :
  log:([> `Rx | `Tx ] ->
       [> `Udp of Eio.Net.Ipaddr.v4v6 * int ] -> Cstruct.t -> unit) ->
  handle_dns:([> `Udp ] ->
              [> `Udp of Eio.Net.Ipaddr.v4v6 * int ] ->
              Cstruct.t -> Cstruct.t list) ->
  #Eio.Net.datagram_socket -> unit

val tcp_handle :
  log:([> `Rx | `Tx ] ->
       [> `Tcp of Eio.Net.Ipaddr.v4v6 * int ] -> Cstruct.t -> unit) ->
  handle_dns:([> `Tcp ] ->
              [> `Tcp of Eio.Net.Ipaddr.v4v6 * int ] ->
              Cstruct.t -> Cstruct.t list) ->
  #Eio.Net.stream_socket ->
  Eio.Net.Sockaddr.stream -> unit

val tcp_listen :
  #Eio.Net.listening_socket ->
  (Eio.Net.stream_socket -> Eio.Net.Sockaddr.stream -> unit) -> unit
