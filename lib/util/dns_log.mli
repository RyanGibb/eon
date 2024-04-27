type dir = Rx | Tx
type log = Format.formatter -> dir -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit
type formattedLog = dir -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit
type level = Level0 | Level1 | Level2 | Level3

(* TODO is there a way to deduplciate these type signatures? *)
val level_0 : log
val level_1 : log
val level_2 : log
val level_3 : log
val get : level -> log
