open Raw
open Capnp_rpc

let local ~sw ~name =
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

       method shell_impl _ release_param_caps =
         let open Host.Shell in
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
         let sink = Eio_unix.Net.import_socket_stream ~sw ~close_unix pty.Pty.masterfd in
         let source = Eio_unix.Net.import_socket_stream ~sw ~close_unix pty.Pty.masterfd in
         let stdin data =
           match Eio.Promise.peek (Eio_linux.Low_level.Process.exit_status shell) with
           | Some i -> Error i
           | None ->
               Eio.Flow.write sink [ (Cstruct.of_string data) ];
               Ok ()
         in
         let buf = Cstruct.create 4096 in
         let stdout () =
           let got = Eio.Flow.single_read source buf in
           Cstruct.to_string (Cstruct.sub buf 0 got)
         in
         let process = Process.local ~stdin ~stdout ~stderr:stdout in

         let response, results = Service.Response.create Results.init_pointer in
         Results.process_set results (Some process);
         Service.return response
     end

let get_info t () =
  let open Api.Client.Host.GetInfo in
  let request = Capability.Request.create_no_args () in
  let ( let* ) = Result.bind in
  let* result = Capability.call_for_value t method_id request in
  Ok (Results.info_get result)

let shell t () =
  let open Api.Client.Host.Shell in
  let request = Capability.Request.create_no_args () in
  Capability.call_for_caps t method_id request Results.process_get_pipelined
