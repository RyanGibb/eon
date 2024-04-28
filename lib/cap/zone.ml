open Raw
open Capnp_rpc_lwt

let local ~sw ~persist_new vat_config services env prod endpoint server_state
    state_dir =
  let module Zone = Api.Service.Zone in
  Zone.local
  @@ object
       inherit Zone.service

       method init_impl params release_param_caps =
         let open Zone.Init in
         let domain = Params.name_get params in
         release_param_caps ();
         Eio.traceln "Service.init(domain='%s')" domain;
         let response, results = Service.Response.create Results.init_pointer in
         (match Domain_name.of_string domain with
         | Error (`Msg e) -> Eio.traceln "Zone error parsing domain: %s" e
         | Ok domain ->
             let sr =
               let id =
                 Capnp_rpc_unix.Vat_config.derived_id vat_config
                   (Domain_name.to_string domain)
               in
               Capnp_rpc_net.Restorer.Table.sturdy_ref services id
             in
             Results.domain_set results
               (Some
                  (Domain.local ~sw ~persist_new sr env domain prod endpoint
                     server_state state_dir)));
         Service.return response
     end

let init t domain =
  let open Api.Client.Zone.Init in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.name_set params (Domain_name.to_string domain);
  Capability.call_for_caps t method_id request Results.domain_get_pipelined
