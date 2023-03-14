module Api = Pipe_api.MakeRPC(Capnp_rpc_lwt)

open Capnp_rpc_lwt

let local ~stdout ~clock =
  let module Pipe = Api.Service.Connection.Pipe in
  Pipe.local @@ object
    inherit Pipe.service

    method read_impl _params release_param_caps =
      let open Pipe.Read in
      release_param_caps ();
      let response, results = Service.Response.create Results.init_pointer in
      Eio.Time.sleep clock 1.0;
      Results.data_set results "-> ...";
      Service.return response

    method write_impl params release_param_caps =
      let open Pipe.Write in
      let data = Params.data_get params in
      Eio.traceln "<- %s" data;
      Eio.Flow.copy_string ("<-" ^ data ^ "\n") stdout;
      release_param_caps ();
      let response, _results = Service.Response.create Results.init_pointer in
      Service.return response

    method close_impl _params release_param_caps =
      let open Pipe.Close in
      release_param_caps ();
      let response, _results = Service.Response.create Results.init_pointer in
      Service.return response

  end

let read t =
  let open Api.Client.Connection.Pipe.Read in
  let request, _params = Capability.Request.create Params.init_pointer in
  match Capability.call_for_value t method_id request with
  | Ok results -> Ok (Results.data_get results)
  | Error e -> Error e

let write t data =
  let open Api.Client.Connection.Pipe.Write in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.data_set params data;
  Capability.call_for_unit t method_id request
