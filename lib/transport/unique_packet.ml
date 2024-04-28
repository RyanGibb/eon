type t = { id : int; seq_no : int; data : Cstruct.t }

let decode buf =
  let id = Cstruct.BE.get_uint16 buf 0 in
  let seq_no = Cstruct.BE.get_uint16 buf 2 in
  let data = Cstruct.sub buf 4 (Cstruct.length buf - 4) in
  { id; seq_no; data }

let encode id seq_no data =
  let buf = Cstruct.create (4 + Cstruct.length data) in
  Cstruct.BE.set_uint16 buf 0 id;
  Cstruct.BE.set_uint16 buf 2 seq_no;
  Cstruct.blit data 0 buf 4 (Cstruct.length data);
  buf
