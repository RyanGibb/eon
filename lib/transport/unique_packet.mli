type t = {
  (* for uniqueness when encoding in query domain names *)
  id : int;
  (* for retransmissions *)
  seq_no : int;
  data : Cstruct.t;
}

val decode : Cstruct.t -> t
val encode : int -> int -> Cstruct.t -> Cstruct.t
