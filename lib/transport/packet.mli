type t = { (* for retransmissions *)
           seq_no : int; data : Cstruct.t }

val decode : Cstruct.t -> t
val encode : int -> Cstruct.t -> Cstruct.t
