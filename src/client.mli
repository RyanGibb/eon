type dns_handler = Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit

val make_query :
  #Eio.Net.datagram_socket ->
  int ->
  'a Dns.Rr_map.rr ->
  string ->
  Eio.Net.Sockaddr.datagram ->
  string ->
  unit

val start :
  #Eio.Net.datagram_socket -> Dns_log.formattedLog -> dns_handler -> unit
