open Cmdliner

val zonefiles : string list Term.t
val log_level : Dns_log.level -> Dns_log.level Term.t
val port : int Term.t
val addresses : string list Term.t
val parse_addresses : int -> string list -> (Eio.Net.Ipaddr.v4v6 * int) list
val proto : [> `Tcp | `Udp ] list Term.t
val resolver : bool Term.t
val man : Manpage.block list
