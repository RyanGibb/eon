let capnp_serve env state_dir vat_config ~sw =
  let services =
    let make_sturdy = Capnp_rpc_unix.Vat_config.sturdy_uri vat_config in
    Capnp_rpc_net.Restorer.Table.create make_sturdy
  in
  let restore = Capnp_rpc_net.Restorer.of_table services in

  let name = Unix.gethostname () in
  let host = Cap.Host.local ~sw ~name in
  let id = Capnp_rpc_unix.Vat_config.derived_id vat_config name in
  Capnp_rpc_net.Restorer.Table.add services id host;
  let vat = Capnp_rpc_unix.serve ~sw ~restore vat_config in

  let cap_dir = Eio.Path.(env#fs / state_dir) in
  Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 cap_dir;
  let _, cap_file = Eio.Path.(cap_dir / (name ^ ".cap")) in
  (match Capnp_rpc_unix.Cap_file.save_service vat id cap_file with
  | Error (`Msg m) -> failwith m
  | Ok () -> ())

let run env state_dir vat_config =
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  Eio.Switch.run @@ fun sw ->
  capnp_serve env state_dir vat_config ~sw;
  Eio.Fiber.await_cancel ()

let () =
  Eio_main.run @@ fun env ->
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs_fmt.reporter ());
  (* Logs.Src.set_level Capnp_rpc.Debug.src (Some Logs.Debug); *)
  let open Cmdliner in
  let cmd =
    let state_dir =
      let doc =
        "Directory to state such as account keys, sturdy refs, and \
         certificates."
      in
      Arg.(value & opt string "state" & info [ "state-dir" ] ~doc)
    in
    let term =
      Term.(
        const (run env) $ state_dir $ Capnp_rpc_unix.Vat_config.cmd env)
    in
    let doc = "shelld" in
    let info = Cmd.info "shelld" ~doc in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
