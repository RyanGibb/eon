type t = { send : Cstruct.t -> unit; recv : Cstruct.t -> int }

let create send recv = { send; recv }
