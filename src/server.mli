
val dns_handler :
  server:Dns_server.Primary.s ref ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  (Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list)

val udp_listen :
  log:Dns_log.formattedLog ->
  handle_dns:(Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list) ->
  #Eio.Net.datagram_socket -> unit

val tcp_handle :
  log:Dns_log.formattedLog ->
  handle_dns:(Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list) ->
  Eio.Flow.two_way -> Eio.Net.Sockaddr.stream ->
  unit
  (* handle an indivudual TCP connection *)

val tcp_listen :
  #Eio.Net.listening_socket ->
  (Eio.Net.stream_socket -> Eio.Net.Sockaddr.stream -> unit) -> unit
  (* Listen on a  *)
