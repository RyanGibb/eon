let run_shell ~stdout ~stdin pty =
  (* handle child stopping *)
  let exception Sigchld in
  let sigchld = Eio.Condition.create () in
  let handle_sigchld (_signum : int) = Eio.Condition.broadcast sigchld in
  ignore (Sys.signal Sys.sigchld (Signal_handle handle_sigchld));

  try
    (* don't close PTY file descriptors *)
    let close_unix = false in
    Eio.Fiber.all
      [
        (fun () ->
          Eio.Switch.run @@ fun sw ->
          let sink = Eio_unix.FD.as_socket ~sw ~close_unix pty.Pty.masterfd in
          Eio.Flow.copy stdin sink);
        (fun () ->
          Eio.Switch.run @@ fun sw ->
          let source = Eio_unix.FD.as_socket ~sw ~close_unix pty.Pty.masterfd in
          Eio.Flow.copy source stdout);
        (fun () ->
          Eio.Condition.await_no_mutex sigchld;
          raise Sigchld);
      ]
  with Sigchld -> ()

let run zonefiles log_level addressStrings subdomain port no_tcp no_udp =
  if no_tcp && no_udp then (
    Format.fprintf Format.err_formatter "Either UDP or TCP should be enabled\n";
    Format.pp_print_flush Format.err_formatter ();
    exit 1);
  let tcp = not no_tcp and udp = not no_udp in
  let log = (Dns_log.get_log log_level) Format.std_formatter in
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let server =
    let addresses = Server_args.parse_addresses port addressStrings in
    let server_state =
      let trie, keys = Zonefile.parse_zonefiles ~fs:env#fs zonefiles in
      let rng ?_g length =
        let buf = Cstruct.create length in
        Eio.Flow.read_exact env#secure_random buf;
        buf
      in
      ref
      @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
           ~tsig_sign:Dns_tsig.sign trie
    in
    Transport.dns_server ~sw ~net:env#net ~clock:env#clock
      ~mono_clock:env#mono_clock ~tcp ~udp subdomain server_state log addresses
  in
  while true do
    (* TODO support parallel with transport support) *)
    let pty = Pty.open_pty () in
    (* spawn shell 'server' as child process *)
    let shell =
      let pw = Unix.getpwuid (Unix.getuid ()) in
      let ptyAction = Fork_actions.setup_shell pty
      and execvAction =
        Eio_linux.Low_level.Process.Fork_action.execve
          pw.pw_shell
          (* The shell name is preceded by '-' to indicate
             that this is a login shell. *)
          ~argv:[| "-bash" |] (* ^ Filename.basename pw.pw_shell *)
          ~env:(Unix.unsafe_environment ())
      in
      Eio_linux.Low_level.Process.spawn ~sw [ ptyAction; execvAction ]
    in
    run_shell ~stdout:server ~stdin:server pty;
    match Eio.Promise.await (Eio_linux.Low_level.Process.exit_status shell) with
    | WEXITED _s | WSIGNALED _s | WSTOPPED _s -> ()
  done

let () =
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let subdomain =
      let doc =
        "Sudomain to use custom processing on. This will be combined with the \
         root DOMAIN to form <SUBDOMAIN>.<DOMAIN>, e.g. rpc.example.org. Data \
         will be encoded as a base 64 string as a sudomain of this domain \
         giving <DATA>.<SUBDOMAIN>.<DOMAIN>, e.g. aGVsbG8K.rpc.example.org."
      in
      Arg.(
        value & opt string "rpc"
        & info [ "sd"; "subdomain" ] ~docv:"SUBDOMAIN" ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ logging $ addresses $ subdomain $ port $ no_tcp
        $ no_udp)
    in
    let info = Cmd.info "sodd" ~man in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
