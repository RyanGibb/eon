
type handle_dns = Dns.proto -> Eio.Net.Sockaddr.t -> Cstruct.t -> Cstruct.t list
(* `handle_dns proto addr query` process a `query` from `addr` sent with transport
   protocol `proto` and returns a list of answers *)

val dns_handler :
  server:Dns_server.Primary.s ref ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  handle_dns
  (* takes a server and clocks and returns a dns handler *)

val udp_listen : Dns_log.formattedLog -> handle_dns -> #Eio.Net.datagram_socket -> unit
  (* listens on a UDP using the handle_dns callback to process queries *)

type connection_handler = Eio.Net.stream_socket -> Eio.Net.Sockaddr.stream -> unit
(* listens on a UDP using the handle_dns callback to process queries *)

val tcp_handle :
  Dns_log.formattedLog -> handle_dns -> connection_handler
  (* handles a single TCP connection using the handle_dns callback to process queries *)

val tcp_listen :
  #Eio.Net.listening_socket -> connection_handler -> unit
  (* listens on a TCP socket and uses the connection_handler callback for incoming connections*)
