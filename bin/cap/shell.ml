type copts = { cap_uri : Uri.t }

let canproto copts_env =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  let run_client cap =
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
    (try
       Eio.Fiber.both
         (fun () ->
           let buf = Cstruct.create 4096 in
           while true do
             let got = Eio.Flow.single_read env#stdin buf in
             Cap.Process.stdin shell (Cstruct.to_string (Cstruct.sub buf 0 got))
           done)
         (fun () ->
           while true do
             let buf = Result.get_ok @@ Cap.Process.stdout shell () in
             Eio.Flow.write env#stdout [ Cstruct.of_string buf ]
           done)
     with _ -> ());
    (* restore tio *)
    Unix.tcsetattr Unix.stdin TCSADRAIN savedTio
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let mosh copts_env =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  let run_client cap =
    match Cap.Host.mosh cap () with
    | Error _ -> ()
    | Ok mosh_connect ->
        Unix.putenv "MOSH_KEY" mosh_connect.key;
        Eio.traceln "%s" mosh_connect.key;
        Unix.execvp "mosh-client" [| "mosh-client"; Ipaddr.to_string mosh_connect.ip; Int32.to_string mosh_connect.port |]
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let help _copts man_format cmds topic =
  match topic with
  | None -> `Help (`Pager, None) (* help about the program. *)
  | Some topic -> (
      let topics = "topics" :: "patterns" :: "environment" :: cmds in
      let conv, _ = Cmdliner.Arg.enum (List.rev_map (fun s -> (s, s)) topics) in
      match conv topic with
      | `Error e -> `Error (false, e)
      | `Ok t when t = "topics" ->
          List.iter print_endline topics;
          `Ok ()
      | `Ok t when List.mem t cmds -> `Help (man_format, Some t)
      | `Ok _t ->
          let page =
            ((topic, 7, "", "", ""), [ `S topic; `P "Say something" ])
          in
          `Ok (Cmdliner.Manpage.print man_format Format.std_formatter page))

open Cmdliner

let help_secs =
  [
    `S "MORE HELP";
    `P "Use $(mname) $(i,COMMAND) --help for help on a single command.";
    `Noblank;
    `P "Use $(mname) $(b,help patterns) for help on patch matching.";
    `Noblank;
    `P "Use $(mname) $(b,help environment) for help on environment variables.";
    `S Manpage.s_bugs;
    `P "Check bug reports at https://github.com/RyanGibb/eon.";
  ]

let copts cap_uri_file env =
  let cap_uri =
    Uri.of_string (Eio.Path.load Eio.Path.(Eio.Stdenv.fs env / cap_uri_file))
  in
  { cap_uri }

let copts_t =
  let _docs = Manpage.s_common_options in
  let cap_uri_file =
    let doc =
      "File path containing the host capability URI of the format \
       capnp://sha-256:<hash>@address:port/<service-ID>."
    in
    Arg.(required & pos 0 (some string) None & info [] ~docv:"CAP_FILE" ~doc)
  in
  Term.(const copts $ cap_uri_file)

let sdocs = Manpage.s_common_options

let capnproto_cmd =
  let doc = "capnproto shell" in
  let info = Cmd.info "caproto" ~doc ~sdocs in
  Cmd.v info Term.(const canproto $ copts_t)

let mosh_cmd =
  let doc = "mosh shell" in
  let info = Cmd.info "mosh" ~doc ~sdocs in
  Cmd.v info Term.(const mosh $ copts_t)

let help_cmd =
  let topic =
    let doc = "The topic to get help on. $(b,topics) lists the topics." in
    Arg.(value & pos 0 (some string) None & info [] ~docv:"TOPIC" ~doc)
  in
  let doc = "display help about shell" in
  let man =
    [
      `S Manpage.s_description; `P "Prints help about shell."; `Blocks help_secs;
    ]
  in
  let info = Cmd.info "help" ~doc ~man in
  Cmd.v info
    Term.(
      ret (const help $ copts_t $ Arg.man_format $ Term.choice_names $ topic))

let main_cmd =
  let doc = "shell" in
  let man = help_secs in
  let info = Cmd.info "shell" ~version:"%%VERSION%%" ~doc ~sdocs ~man in
  let default = Term.(ret (const (fun _ -> `Help (`Pager, None)) $ copts_t)) in
  Cmd.group info ~default [ capnproto_cmd; mosh_cmd; help_cmd ]

let () = exit (Cmd.eval main_cmd)
