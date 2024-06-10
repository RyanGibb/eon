open Raw
open Capnp_rpc_lwt

let local ~sw ~persist_new_domain sr env domain prod endpoint server_state
    state_dir primary =
  let module Domain = Api.Service.Domain in
  Persistence.with_sturdy_ref sr Domain.local
  @@ object
       inherit Domain.service

       method get_name_impl _params release_param_caps =
         let open Domain.GetName in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         Results.name_set results (Domain_name.to_string domain);
         Service.return response

       method cert_impl params release_param_caps =
         let open Domain.Cert in
         let email = Params.email_get params in
         let org =
           match Params.org_get params with "" -> None | o -> Some o
         in
         let domains = Params.domains_get_list params in
         let callback = Params.cert_callback_get params in
         release_param_caps ();
         Eio.traceln "Domain.cert(email=%s, org=%a, domains=[%a]) in domain=%a"
           email (Fmt.option Fmt.string) org (Fmt.list Fmt.string) domains
           Domain_name.pp domain;
         Cert.cert ~sw env prod endpoint server_state state_dir callback email
           org domains

       method delegate_impl params release_param_caps =
         let open Domain.Delegate in
         let subdomain = Params.subdomain_get params in
         release_param_caps ();
         Eio.traceln "Domain.delegate(subdomain='%s')" subdomain;
         match Domain_name.of_string subdomain with
         | Error (`Msg e) ->
             Eio.traceln "Domain.delegate error parsing domain: %s" e;
             Service.fail "Error parsing domain"
         | Ok subdomain -> (
             let name = Domain_name.append_exn subdomain domain in
             (* we create a new capabilty for every request, not every domain,
                so they can be revoked per-client *)
             match persist_new_domain ~name primary with
             | Error e -> Service.error (`Exception e)
             | Ok delegated ->
                 let response, results =
                   Service.Response.create Results.init_pointer
                 in
                 Results.domain_set results (Some delegated);
                 Capability.dec_ref delegated;
                 Service.return response)

       method update_impl params release_param_caps =
         let open Domain.Update in
         let prereqs = Params.prereqs_get params in
         let updates = Params.updates_get params in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         (match Update.update_trie env server_state domain prereqs updates with
         | exception Invalid_argument msg ->
             Results.success_set results false;
             Results.error_set results msg
         | exception e ->
             let msg = Printexc.to_string e in
             Results.success_set results false;
             Results.error_set results msg
         | prereqs, updates -> (
             match Primary.update_secondaries primary prereqs updates with
             | Error (`Capnp e) ->
                 Eio.traceln "Error calling Primary.update_secondaries: %a"
                   Capnp_rpc.Error.pp e;
                 Results.error_set results
                   (Fmt.str "Error calling Primary.update_secondaries: %a"
                      Capnp_rpc.Error.pp e)
             | Error (`Remote e) ->
                 Eio.traceln "Error calling Primary.update_secondaries: %s" e;
                 Results.error_set results
                   ("Error calling Primary.update_secondaries: " ^ e)
             | Ok () -> Results.success_set results true));
         Service.return response
     end

let get_name t =
  let open Api.Client.Domain.GetName in
  let request = Capability.Request.create_no_args () in
  match Capability.call_for_value t method_id request with
  | Ok results -> Ok (Results.name_get results)
  | Error e -> Error e

let cert t ~email ~org domains cert_callback =
  let open Api.Client.Domain.Cert in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.email_set params email;
  ignore
  @@ Params.domains_set_list params (List.map Domain_name.to_string domains);
  Params.org_set params (match org with None -> "" | Some o -> o);
  Params.cert_callback_set params (Some cert_callback);
  Capability.call_for_unit t method_id request

let delegate t subdomain =
  let open Api.Client.Domain.Delegate in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.subdomain_set params (Domain_name.to_string subdomain);
  Capability.call_for_caps t method_id request Results.domain_get_pipelined

let update t prereqs updates =
  let open Api.Client.Domain.Update in
  let request, params = Capability.Request.create Params.init_pointer in
  ignore @@ Params.prereqs_set_list params (Update.encode_prereqs prereqs);
  ignore @@ Params.updates_set_list params (Update.encode_updates updates);
  match Capability.call_for_value t method_id request with
  | Ok results -> (
      match Results.success_get results with
      | true -> Ok ()
      | false ->
          let error = Results.error_get results in
          Error (`Remote error))
  | Error e -> Error e
