type 'a dns_handler = Dns.proto -> Eio.Net.Sockaddr.t -> string -> 'a -> 'a

val send_query :
  Dns_log.formattedLog ->
  int ->
  'a Dns.Rr_map.rr ->
  'b Domain_name.t ->
  _ Eio.Net.datagram_socket ->
  Eio.Net.Sockaddr.datagram ->
  unit

val listen :
  _ Eio.Net.datagram_socket ->
  Dns_log.formattedLog ->
  'a dns_handler ->
  'a ->
  unit
