type t = { items : Cstruct.t list ref; mut : Eio.Mutex.t; cond : Eio.Condition.t }

exception Empty

let create () = { items = ref []; mut = Eio.Mutex.create (); cond = Eio.Condition.create () }

let add t bufs =
  Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
      t.items := !(t.items) @ bufs;
      Eio.Condition.broadcast t.cond)

let take t buf =
  Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
      (* if `Cstruct.lenv !(t.items) == 0` we just send an empty packet *)
      while !(t.items) == [] do
        Eio.Condition.await t.cond t.mut
      done;
      let read, new_items = Cstruct.fillv ~src:!(t.items) ~dst:buf in
      t.items := new_items;
      read)

let try_take q buf =
  let read, empty =
    Eio.Mutex.use_rw ~protect:false q.mut (fun () ->
        (* if `Cstruct.lenv !(q.items) == 0` we just send an empty packet *)
        if !(q.items) == [] then (0, true)
        else
          let read, new_items = Cstruct.fillv ~src:!(q.items) ~dst:buf in
          q.items := new_items;
          (read, false))
  in
  if empty then None else Some read

let take_one t buf =
  Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
      let rec f () =
        match !(t.items) with
        | [] ->
            Eio.Condition.await t.cond t.mut;
            f ()
        | packet :: new_items ->
            let packet_len = Cstruct.length packet in
            (* will raise if buf isn't big enough to hold packet *)
            Cstruct.blit packet 0 buf 0 packet_len;
            t.items := new_items;
            packet_len
      in
      f ())

let try_take_one t =
  Eio.Mutex.use_rw t.mut ~protect:false (fun () ->
      match !(t.items) with
      | [] -> None
      | packet :: new_items ->
          t.items := new_items;
          Some packet)
