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
          let sink =
            Eio_unix.Net.import_socket_stream ~sw ~close_unix pty.Pty.masterfd
          in
          Eio.Flow.copy stdin sink);
        (fun () ->
          Eio.Switch.run @@ fun sw ->
          let source =
            Eio_unix.Net.import_socket_stream ~sw ~close_unix pty.Pty.masterfd
          in
          Eio.Flow.copy source stdout);
        (fun () ->
          Eio.Condition.await_no_mutex sigchld;
          raise Sigchld);
      ]
  with Sigchld -> ()

let run zonefiles log_level address_strings subdomain authorative port proto =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let log = Dns_log.get log_level Format.std_formatter in
  let server =
    let addresses = Server_args.parse_addresses port address_strings in
    let server_state =
      let trie', keys, parsedAuthorative =
        Zonefile.parse_zonefiles ~fs:env#fs zonefiles
      in
      let trie =
        match List.find_opt (fun a -> a == authorative) parsedAuthorative with
        | Some _ -> trie'
        | None ->
            Dns_trie.insert Domain_name.root Dns.Rr_map.Soa
              (Dns.Soa.create authorative)
              trie'
      in
      let rng ?_g length =
        let buf = Cstruct.create length in
        Eio.Flow.read_exact env#secure_random buf;
        Cstruct.to_string buf
      in
      ref
      @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
           ~tsig_sign:Dns_tsig.sign trie
    in
    let authorative = Domain_name.to_string authorative in
    Transport.Stream_server.run ~sw env proto ~subdomain ~authorative
      server_state log addresses
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
    let authorative =
      let doc = "Domain for which the server is authorative." in
      Arg.(
        required
        & opt (some (conv (Domain_name.of_string, Domain_name.pp))) None
        & info [ "a"; "authorative" ] ~docv:"AUTHORATIVE" ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.Level1 $ addresses $ subdomain
        $ authorative $ port $ proto)
    in
    let info = Cmd.info "sodd" ~man in
    Cmd.v info term
  in
  exit (Cmdliner.Cmd.eval cmd)
