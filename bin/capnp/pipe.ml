module Api = Pipe_api.MakeRPC (Capnp_rpc_lwt)
open Capnp_rpc_lwt

module Stream = struct
  let local ~stdout ~clock =
    let module Stream = Api.Service.Connection.Stream in
    Stream.local
    @@ object
         inherit Stream.service

         method read_impl _params release_param_caps =
           let open Stream.Read in
           release_param_caps ();
           let response, results =
             Service.Response.create Results.init_pointer
           in
           Eio.Time.sleep clock 1.0;
           Results.data_set results "-> ...";
           Service.return response

         method write_impl params release_param_caps =
           let open Stream.Write in
           let data = Params.data_get params in
           Eio.traceln "<- %s" data;
           Eio.Flow.copy_string ("<-" ^ data ^ "\n") stdout;
           release_param_caps ();
           let response, _results =
             Service.Response.create Results.init_pointer
           in
           Service.return response

         method close_impl _params release_param_caps =
           let open Stream.Close in
           release_param_caps ();
           let response, _results =
             Service.Response.create Results.init_pointer
           in
           Service.return response
       end

  let read t =
    let open Api.Client.Connection.Stream.Read in
    let request, _params = Capability.Request.create Params.init_pointer in
    match Capability.call_for_value t method_id request with
    | Ok results -> Ok (Results.data_get results)
    | Error e -> Error e

  let write t data =
    let open Api.Client.Connection.Stream.Write in
    let request, params = Capability.Request.create Params.init_pointer in
    Params.data_set params data;
    Capability.call_for_unit t method_id request
end

module Connection = struct
  let local ~stdout ~clock =
    let module Connection = Api.Service.Connection in
    Connection.local
    @@ object
         inherit Connection.service

         method create_impl _params release_param_caps =
           let open Connection.Create in
           release_param_caps ();
           let stream = Stream.local ~stdout ~clock in
           let response, results =
             Service.Response.create Results.init_pointer
           in
           Results.stream_set results (Some stream);
           Service.return response
       end

  let create t =
    let open Api.Client.Connection.Create in
    let request, _params = Capability.Request.create Params.init_pointer in
    Capability.call_for_caps t method_id request Results.stream_get_pipelined
end