val zonefiles : string list Cmdliner.Term.t
val logging_default : int -> int Cmdliner.Term.t
val logging : int Cmdliner.Term.t
val port : int Cmdliner.Term.t
val addresses : string list Cmdliner.Term.t
val parse_addresses : int -> string list -> (Eio.Net.Ipaddr.v4v6 * int) list
val no_tcp : bool Cmdliner.Term.t
val no_udp : bool Cmdliner.Term.t
val man : Cmdliner.Manpage.block list
