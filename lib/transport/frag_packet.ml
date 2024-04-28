type packet = {
  id : int;
  n_frags : int;  (** how many fragments to expect for this packet *)
}

type t =
  | Packet of {
      packet : packet;
      frag_nb : int;  (** identifying fragment in packet *)
      data : Cstruct.t;
    }
  | Dummy of { id : int }

let decode buf =
  let id = Cstruct.BE.get_uint16 buf 0 in
  let frag_nb = Cstruct.BE.get_uint16 buf 2 in
  let n_frags = Cstruct.BE.get_uint16 buf 4 in
  match n_frags with
  | 0 -> Dummy { id }
  | _ ->
      let packet = { id; n_frags } in
      let data = Cstruct.sub buf 6 (Cstruct.length buf - 6) in
      Packet { packet; frag_nb; data }

let encode frag =
  match frag with
  | Dummy { id } ->
      let buf = Cstruct.create 6 in
      let frag_nb = 0 in
      let n_frags = 0 in
      Cstruct.BE.set_uint16 buf 0 id;
      Cstruct.BE.set_uint16 buf 2 frag_nb;
      Cstruct.BE.set_uint16 buf 4 n_frags;
      buf
  | Packet { packet; frag_nb; data } ->
      let { id; n_frags } = packet in
      let buf = Cstruct.create (6 + Cstruct.length data) in
      Cstruct.BE.set_uint16 buf 0 id;
      Cstruct.BE.set_uint16 buf 2 frag_nb;
      Cstruct.BE.set_uint16 buf 4 n_frags;
      Cstruct.blit data 0 buf 6 (Cstruct.length data);
      buf

let dummy id = Dummy { id }
