type t = Eio.Flow.two_way_ty Eio.Resource.t

let create ~inc ~out =
  let module CstructFlow = struct
    type t = unit

    let copy _t ~src =
      let buf = Cstruct.create 4096 in
      try
        while true do
          let got = Eio.Flow.single_read src buf in
          Cstruct_stream.add out [ Cstruct.sub buf 0 got ]
        done
      with End_of_file -> ()

    let single_write _t bufs =
      Cstruct_stream.add out bufs;
      List.fold_left (fun acc buf -> acc + Cstruct.length buf) 0 bufs

    let read_methods = []
    let single_read _t buf = Cstruct_stream.take inc buf
    let shutdown _t _cmd = ()
  end in
  let ops = Eio.Flow.Pi.two_way (module CstructFlow) in
  Eio.Resource.T ((), ops)
