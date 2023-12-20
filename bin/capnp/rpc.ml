let cap_file = "pipe.cap"

let serve config =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let service_id = Capnp_rpc_unix.Vat_config.derived_id config "main" in
  let restore =
    Capnp_rpc_net.Restorer.single service_id
      (Pipe.Connection.local ~clock:(Eio.Stdenv.clock env)
         ~stdout:(Eio.Stdenv.stdout env))
  in
  let vat = Capnp_rpc_unix.serve ~sw ~net:env#net ~restore config in
  match Capnp_rpc_unix.Cap_file.save_service vat service_id cap_file with
  | Error (`Msg m) -> failwith m
  | Ok () ->
      Eio.traceln "Server running. Connect using %S." cap_file;
      Eio.Fiber.await_cancel ()

open Cmdliner

let serve_cmd =
  let doc = "run the server" in
  let info = Cmd.info "serve" ~doc in
  Cmd.v info Term.(const serve $ Capnp_rpc_unix.Vat_config.cmd)

let () = exit (Cmd.eval serve_cmd)
