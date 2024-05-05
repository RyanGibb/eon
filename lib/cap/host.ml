open Raw
open Capnp_rpc_lwt

let local env name server_state =
  let module Host = Api.Service.Host in
  Host.local
  @@ object
       inherit Host.service

       method get_fqdn_impl _params release_param_caps =
         let open Host.GetFqdn in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         Results.fqdn_set results (Domain_name.to_string name);
         Service.return response

       method get_update_cap_impl _params release_param_caps =
         let open Host.GetUpdateCap in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         let update = Update_cap.local env name server_state in
         Results.update_cap_set results (Some update);
         Service.return response

       method status_impl params release_param_caps =
         let open Host.Status in
         let _status = Params.status_get params in
         release_param_caps ();
         Eio.traceln "Host.status(name='%a')" Domain_name.pp name;
         Service.return_empty ()
     end

let get_fqdn t =
  let open Api.Client.Host.GetFqdn in
  let request, _params = Capability.Request.create Params.init_pointer in
  match Capability.call_for_value t method_id request with
  | Ok results -> Ok (Results.fqdn_get results)
  | Error e -> Error e

type location = { lat : float; long : float }
type status = { load : float; carbon_intensity : float; location : location }

let status t status =
  let open Api.Client.Host.Status in
  let request, params = Capability.Request.create Params.init_pointer in
  let open Api.Builder in
  let host_status = Params.status_init params in
  HostStatus.load_set host_status status.load;
  HostStatus.carbon_intensity_set host_status status.carbon_intensity;
  let location = HostStatus.location_init host_status in
  HostStatus.Location.lat_set location status.location.lat;
  HostStatus.Location.long_set location status.location.long;
  Capability.call_for_unit t method_id request
