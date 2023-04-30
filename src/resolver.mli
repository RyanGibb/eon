val start :
  net:#Eio.Net.t ->
  clock:#Eio.Time.clock ->
  mono_clock:#Eio.Time.Mono.t ->
  ?tcp:bool ->
  ?udp:bool ->
  Dns_resolver.t ref ->
  (Dns_log.dir ->
  [> `Tcp of Eio.Net.Ipaddr.v4v6 * int
  | `Udp of Eio.Net.Ipaddr.v4v6 * int
  | `Unix of string ] ->
  Cstruct.t ->
  unit) ->
  (Eio.Net.Ipaddr.v4v6 * int) list ->
  unit
