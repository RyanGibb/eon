open Raw
open Capnp_rpc_lwt

let local provision_cert =
  let module Zone = Api.Service.Zone in
  Zone.local @@ object
    inherit Zone.service

    method init_impl params release_param_caps =
      let open Zone.Init in
      let domain = Params.name_get params; in
      release_param_caps ();
      Eio.traceln "Service.init(domain='%s')" domain;
      let response, results =
        Service.Response.create Results.init_pointer
      in
      (match Domain_name.of_string domain with
      | Error (`Msg e) ->
        Eio.traceln "Zone error parsing domain: %s" e
      | Ok domain ->
        Results.domain_set results (Some (Domain.local domain provision_cert)));
      Service.return response
  end

let init t domain =
  let open Api.Client.Zone.Init in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.name_set params (Domain_name.to_string domain);
  Capability.call_for_caps t method_id request Results.domain_get_pipelined

