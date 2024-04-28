type t = { seq_no : int; data : Cstruct.t }

let decode buf =
  let seq_no = Cstruct.BE.get_uint16 buf 0 in
  let data = Cstruct.sub buf 2 (Cstruct.length buf - 2) in
  { seq_no; data }

let encode seq_no data =
  let buf = Cstruct.create (2 + Cstruct.length data) in
  Cstruct.BE.set_uint16 buf 0 seq_no;
  Cstruct.blit data 0 buf 2 (Cstruct.length data);
  buf
