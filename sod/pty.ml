(* Pseudo terminal handling functions *)
type pty = {
  masterfd : Unix.file_descr;
  slavefd : Unix.file_descr;
  name : string;
}

type pty_window = { row : int32; col : int32; xpixel : int32; ypixel : int32 }

(* Exceptions raised by Pty functions *)
exception Pty_error of string

let _ = Callback.register_exception "pty_error" (Pty_error "")

(* External declarations of Pty bindings *)
external open_pty : unit -> pty = "pty_open_pty"
external switch_controlling_pty : pty -> unit = "pty_switch_controlling_tty"
external set_window_size : pty -> pty_window -> unit = "pty_window_size"
external tty_window_size : unit -> pty_window = "pty_tty_window_size"
external get_sigwinch : unit -> int option = "ocaml_terminal_get_sigwinch"

(* Convenience ML functions *)
let close_pty pty =
  try Unix.close pty.masterfd
  with _ -> (
    ();
    try Unix.close pty.slavefd with _ -> ())

(* Internal declarations of Pty bindings *)
let string_of_pty p = Printf.sprintf "name=%s" p.name
