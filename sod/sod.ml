let run log_level domain subdomain port nameserver =
  let log = (Dns_log.get_log log_level) Format.std_formatter in
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let client =
    Transport.dns_client ~sw ~net:env#net ~clock:env#clock
      ~random:env#secure_random nameserver subdomain domain port log
  in

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
      (* c_iuclc = false; *)
      c_ixoff = false;
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
    (fun () -> Eio.Flow.copy env#stdin client)
    (fun () -> Eio.Flow.copy client env#stdout);

  (* restore tio *)
  Unix.tcsetattr Unix.stdin TCSADRAIN savedTio

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
    let domain =
      let doc = "Domain that the NAMESERVER is authorative for." in
      Arg.(
        value & opt string "example.org"
        & info [ "d"; "domain" ] ~docv:"DOMAIN" ~doc)
    in
    let nameserver =
      let doc =
        "The address of the nameserver to query. The first result returned by \
         getaddrinfo will be used. If this may return multiple values, e.g. an \
         IPv4 and IPv6 address for a host, and a specific one is desired it \
         should be specified."
      in
      Arg.(
        value & opt string "127.0.0.1"
        & info [ "n"; "nameserver" ] ~docv:"NAMESERVER" ~doc)
    in
    let term =
      Term.(
        const run $ logging_default 0 $ domain $ subdomain $ port $ nameserver)
    in
    let info = Cmd.info "sod" ~man in
    Cmd.v info term
  in
  (* this is not domain safe *)
  (* Logs.set_reporter (Logs_fmt.reporter ());
     Logs.set_level (Some Logs.Error); *)
  exit (Cmdliner.Cmd.eval cmd)
