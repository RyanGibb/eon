type t = { items : Cstruct.t list ref; mut : Eio.Mutex.t; cond : Eio.Condition.t }

exception Empty

val create : unit -> t
val add : t -> Cstruct.t list -> unit
val take : t -> Cstruct.t -> int
val try_take : t -> Cstruct.t -> int option
val take_one : t -> Cstruct.t -> int
val try_take_one : t -> Cstruct.t option
