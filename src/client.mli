type dns_handler = Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit

val send_query :
  Dns_log.formattedLog ->
  int ->
  'a Dns.Rr_map.rr ->
  'b Domain_name.t ->
  #Eio.Net.datagram_socket ->
  Eio.Net.Sockaddr.datagram ->
  unit

val listen :
  #Eio.Net.datagram_socket -> Dns_log.formattedLog -> dns_handler -> unit
