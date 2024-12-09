let run_client ~env cap =
  let shell = Cap.Host.shell cap () in
  let savedTio = Unix.tcgetattr Unix.stdin in

  (* set raw mode *)
  let tio =
    {
      savedTio with
      (* input modes *)
      c_ignpar = true;
      c_istrip = false;
      c_inlcr = false;
      c_igncr = false;
      c_ixon = false;
      (* c_ixany = false; *)
      (* c_iuclc = false; *) c_ixoff = false;
      (* output modes *)
      c_opost = false;
      (* control modes *)
      c_isig = false;
      c_icanon = false;
      c_echo = false;
      c_echoe = false;
      c_echok = false;
      c_echonl = false;
      (* c_iexten = false; *)

      (* special characters *)
      c_vmin = 1;
      c_vtime = 0;
    }
  in
  Unix.tcsetattr Unix.stdin TCSADRAIN tio;

  (* TODO send window size change update https://www.ietf.org/rfc/rfc4254.html#section-6.7 *)
  (* handle window size change *)
  (* match Pty.get_sigwinch () with
     | None -> ()
     | Some sigwinch -> (
         let handle_sigwinch (_signum : int) =
           let ws = Pty.tty_window_size () in
           ignore (Pty.set_window_size pty ws)
         in
         handle_sigwinch sigwinch;
         ignore (Sys.signal sigwinch (Signal_handle handle_sigwinch))); *)

  (* TODO detect terminated session *)
  (* TODO use nagle's algorithm? *)
  Eio.Fiber.both
    (fun () ->
      let buf = Cstruct.create 4096 in
      try
        while true do
          let got = Eio.Flow.single_read env#stdin buf in
          Cap.Process.stdin shell (Cstruct.to_string (Cstruct.sub buf 0 got))
        done
      with End_of_file -> ())
    (fun () ->
      try
        while true do
          let buf = Result.get_ok @@ Cap.Process.stdout shell () in
          Eio.Flow.write env#stdout [ Cstruct.of_string buf ]
        done
      with End_of_file -> ());

  (* restore tio *)
  Unix.tcsetattr Unix.stdin TCSADRAIN savedTio

let run cap_uri_file =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let cap_uri =
    Uri.of_string (Eio.Path.load Eio.Path.(Eio.Stdenv.fs env / cap_uri_file))
  in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref (run_client ~env)

let () =
  let open Cmdliner in
  let cmd =
    let cap_uri_file =
      let doc =
        "File path containing the domain capability URI of the format \
         capnp://sha-256:<hash>@address:port/<service-ID>."
      in
      Arg.(required & pos 0 (some string) None & info [] ~docv:"CAP_FILE" ~doc)
    in
    let term = Term.(const run $ cap_uri_file) in
    let doc = "shelld" in
    let info = Cmd.info "shelld" ~doc in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
