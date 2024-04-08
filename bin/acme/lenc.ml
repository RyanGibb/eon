let run email org domain socket_path =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let sock = Eio.Net.connect ~sw env#net (`Unix socket_path) in

  let request =
    String.concat "\n" [ email; org; Domain_name.to_string domain ]
  in
  Eio.Flow.copy_string request sock;
  Eio.Flow.shutdown sock `Send;

  let response =
    let buffer = Eio.Buf_read.of_flow ~max_size:4096 sock in
    Eio.Buf_read.line buffer
  in
  Printf.printf "%s\n" response;
  Eio.Flow.shutdown sock `All

let () =
  let open Cmdliner in
  let cmd =
    let email =
      let doc = "The email address to use for the ACME account." in
      Arg.(required & pos 0 (some string) None & info [] ~docv:"EMAIL" ~doc)
    in
    let org =
      let doc = "The name of the organization requesting the certificate." in
      Arg.(
        required & pos 1 (some string) None & info [] ~docv:"ORGANIZATION" ~doc)
    in
    let domain =
      let doc = "The domain for which to request the certificate." in
      Arg.(
        required
        & pos 3 (some (conv (Domain_name.of_string, Domain_name.pp))) None
        & info [] ~docv:"DOMAIN" ~doc)
    in
    let socket_path =
      let doc = "The path to the Unix domain socket." in
      Arg.(
        value
        & opt string "/run/lend/cert.socket"
        & info [ "s"; "socket" ] ~docv:"SOCKET_PATH" ~doc)
    in
    let term = Term.(const run $ email $ org $ domain $ socket_path) in
    let doc = "Let's Encrypt Nameserver Client." in
    let info = Cmd.info "lenc" ~doc in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
