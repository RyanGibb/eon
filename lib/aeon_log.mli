
(* TODO is there a way to deduplciate these type signatures? *)
val log_level_0 : Format.formatter -> [< `Rx | `Tx ] -> [< Eio.Net.Sockaddr.t ] -> Cstruct.t -> unit
val log_level_1 : Format.formatter -> [< `Rx | `Tx ] -> [< Eio.Net.Sockaddr.t ] -> Cstruct.t -> unit
val log_level_2 : Format.formatter -> [< `Rx | `Tx ] -> [< Eio.Net.Sockaddr.t ] -> Cstruct.t -> unit
val log_level_3 : Format.formatter -> [< `Rx | `Tx ] -> [< Eio.Net.Sockaddr.t ] -> Cstruct.t -> unit
