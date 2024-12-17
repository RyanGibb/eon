open Raw
open Capnp_rpc

let local ~env ~sw ~name ~mosh_addr =
  let module Host = Api.Service.Host in
  Host.local
  @@ object
       inherit Host.service

       method get_info_impl _ release_param_caps =
         let open Host.GetInfo in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         let info = Results.info_init results in
         Api.Builder.HostInfo.name_set info name;
         Service.return response

       method shell_impl params release_param_caps =
         let open Host.Shell in
         let exitCallback = Option.get @@ Params.exit_callback_get params in
         release_param_caps ();

         let pty = Pty.open_pty () in
         (* spawn shell as child process *)
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
         (* don't close PTY file descriptors *)
         let close_unix = false in
         let sink =
           Eio_unix.Net.import_socket_stream ~sw ~close_unix pty.Pty.masterfd
         in
         let source =
           Eio_unix.Net.import_socket_stream ~sw ~close_unix pty.Pty.masterfd
         in
         let stdin data = Eio.Flow.write sink [ Cstruct.of_string data ] in

         Eio.Fiber.fork ~sw (fun () ->
           let e = Eio.Promise.await (Eio_linux.Low_level.Process.exit_status shell) in
           match Exit_callback.exitStatus exitCallback e with
           | Ok () -> ()
           | Error (`Capnp e) ->
               Eio.traceln "Error calling Exit_callback.exitStatus %a"
                 Capnp_rpc.Error.pp e;
         );

         let buf = Cstruct.create 4096 in
         let stdout () =
           let got = Eio.Flow.single_read source buf in
           Cstruct.to_string (Cstruct.sub buf 0 got)
         in
         let process = Process.local ~stdin ~stdout ~stderr:stdout in

         let response, results = Service.Response.create Results.init_pointer in
         Results.process_set results (Some process);
         Service.return response

       method mosh_impl _ release_param_caps =
         let open Host.Mosh in
         release_param_caps ();
         match mosh_addr with
         | None -> Service.fail ""
         | Some mosh_addr ->
             let proc_mgr = Eio.Stdenv.process_mgr env in
             let buf = Buffer.create 80 in
             let () =
               Eio.Process.run proc_mgr ~stdout:(Eio.Flow.buffer_sink buf)
                 [ "mosh-server" ]
             in
             let string = Buffer.contents buf in
             let split = String.split_on_char ' ' string in
             let port = Int32.of_string (List.nth split 2) in
             let key = String.trim (String.concat "" (String.split_on_char '\n' (List.nth split 3))) in
             let response, results =
               Service.Response.create Results.init_pointer
             in
             let mosh_connect = Results.mosh_connect_init results in
             Api.Builder.MoshConnect.ip_set mosh_connect (Ipaddr.to_string mosh_addr);
             Api.Builder.MoshConnect.port_set mosh_connect port;
             Api.Builder.MoshConnect.key_set mosh_connect key;
             Service.return response
     end

let get_info t () =
  let open Api.Client.Host.GetInfo in
  let request = Capability.Request.create_no_args () in
  let ( let* ) = Result.bind in
  let* result = Capability.call_for_value t method_id request in
  Ok (Results.info_get result)

let shell t exitCallback =
  let open Api.Client.Host.Shell in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.exit_callback_set params (Some exitCallback);
  Capability.call_for_caps t method_id request Results.process_get_pipelined

type mosh_connect = {
  ip : Ipaddr.t;
  port : int32;
  key : string;
}

let mosh t () =
  let open Api.Client.Host.Mosh in
  let request = Capability.Request.create_no_args () in
  let ( let* ) = Result.bind in
  let* result = Capability.call_for_value t method_id request in
  let mosh_connect = Results.mosh_connect_get result in
  let* ip = Ipaddr.of_string (Api.Reader.MoshConnect.ip_get mosh_connect) in
  let port = Api.Reader.MoshConnect.port_get mosh_connect in
  let key = Api.Reader.MoshConnect.key_get mosh_connect in
  Ok { ip; port; key }
