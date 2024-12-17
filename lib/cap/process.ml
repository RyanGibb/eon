open Raw
open Capnp_rpc

let local ~stdin ~stdout ~stderr =
  let module Process = Api.Service.Process in
  Process.local
  @@ object
       inherit Process.service

       method stdout_impl _ release_param_caps =
         let open Process.Stdout in
         release_param_caps ();
         let s = stdout () in
         let response, results = Service.Response.create Results.init_pointer in
         Results.data_set results s;
         Service.return response

       method stderr_impl _ release_param_caps =
         let open Process.Stderr in
         release_param_caps ();
         let s = stderr () in
         let response, results = Service.Response.create Results.init_pointer in
         Results.data_set results s;
         Service.return response

       method stdin_impl params release_param_caps =
         let open Process.Stdin in
         let data = Params.data_get params in
         release_param_caps ();
         stdin data;
         Service.return_empty ()
     end

let stdout t () =
  let open Api.Client.Process.Stdout in
  let request = Capability.Request.create_no_args () in
  let ( let* ) = Result.bind in
  let* result = Capability.call_for_value t method_id request in
  Ok (Results.data_get result)

let stderr t () =
  let open Api.Client.Process.Stderr in
  let request = Capability.Request.create_no_args () in
  let ( let* ) = Result.bind in
  let* result = Capability.call_for_value t method_id request in
  Ok (Results.data_get result)

let stdin t data =
  let open Api.Client.Process.Stdin in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.data_set params data;
  Capability.call_for_unit_exn t method_id request
