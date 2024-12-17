open Raw
open Capnp_rpc

let local callback =
  let module ExitCallback = Api.Service.ExitCallback in
  ExitCallback.local
  @@ object
       inherit ExitCallback.service

       method exit_status_impl params release_param_caps =
         let open ExitCallback.ExitStatus in
         callback
           (match Api.Reader.ExitStatus.get (Params.exit_status_get params) with
           | Exited i ->
               let code =
                 Int32.to_int (Api.Reader.ExitStatus.Exited.code_get i)
               in
               Ok (Unix.WEXITED code)
           | Signaled i ->
               let code =
                 Int32.to_int (Api.Reader.ExitStatus.Signaled.code_get i)
               in
               Ok (Unix.WSIGNALED code)
           | Stopped i ->
               let code =
                 Int32.to_int (Api.Reader.ExitStatus.Stopped.code_get i)
               in
               Ok (Unix.WSTOPPED code)
           | _ -> Error "unknown value");
         release_param_caps ();
         Service.return_empty ()
     end

let exitStatus t status =
  let open Api.Client.ExitCallback.ExitStatus in
  let request, params = Capability.Request.create Params.init_pointer in
  let exitStatus = Params.exit_status_init params in
  (match status with
  | Unix.WEXITED i ->
      Eio.traceln "exited %d" i;
      let exited = Api.Builder.ExitStatus.exited_init exitStatus in
      Api.Builder.ExitStatus.Exited.code_set exited (Int32.of_int i)
  | Unix.WSIGNALED i ->
      Eio.traceln "signaled %d" i;
      let signaled = Api.Builder.ExitStatus.exited_init exitStatus in
      Api.Builder.ExitStatus.Exited.code_set signaled (Int32.of_int i)
  | Unix.WSTOPPED i ->
      Eio.traceln "stopped %d" i;
      let stopped = Api.Builder.ExitStatus.exited_init exitStatus in
      Api.Builder.ExitStatus.Exited.code_set stopped (Int32.of_int i));
  Capability.call_for_unit t method_id request
