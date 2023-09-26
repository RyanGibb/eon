(* TODO upstream PTY support: https://github.com/ocaml-multicore/eio/pull/461#issuecomment-1497427461  *)

external action_setup_shell : unit -> Eio_unix.Private.Fork_action.fork_fn
  = "eio_unix_fork_setup_shell"

let action_setup_shell = action_setup_shell ()

let setup_shell pty : Eio_unix.Private.Fork_action.t =
  { run = (fun k -> k (Obj.repr (action_setup_shell, pty))) }
