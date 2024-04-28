type t = { send : Cstruct.t -> unit; recv : Cstruct.t -> int }

val create : (Cstruct.t -> unit) -> (Cstruct.t -> int) -> t
