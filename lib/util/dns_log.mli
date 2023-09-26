type dir = Rx | Tx
type log = Format.formatter -> dir -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit
type formattedLog = dir -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit

(* TODO is there a way to deduplciate these type signatures? *)
val log_level_0 : log
val log_level_1 : log
val log_level_2 : log
val log_level_3 : log
val get_log : int -> log
