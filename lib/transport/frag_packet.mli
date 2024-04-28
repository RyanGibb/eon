type packet = { id : int; n_frags : int  (** how many fragments to expect for this packet *) }

type t =
  | Packet of { packet : packet; frag_nb : int;  (** identifying fragment in packet *) data : Cstruct.t }
  (* we need a packet id for the client to send unique dummy packets to avoid caching *)
  | Dummy of { id : int }

val decode : Cstruct.t -> t
val encode : t -> Cstruct.t
val dummy : int -> t
