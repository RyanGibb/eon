open Raw
open Capnp_rpc_lwt

let local sr env domain server_state =
  let module Secondary = Api.Service.Secondary in
  Persistence.with_sturdy_ref sr Secondary.local
  @@ object
       inherit Secondary.service

       method get_name_impl _params release_param_caps =
         let open Secondary.GetName in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         Results.name_set results (Domain_name.to_string domain);
         Service.return response

       method update_impl params release_param_caps =
         let open Secondary.Update in
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
         | _ -> Results.success_set results true);
         Service.return response
     end

let get_name t =
  let open Api.Client.Secondary.GetName in
  let request, _params = Capability.Request.create Params.init_pointer in
  match Capability.call_for_value t method_id request with
  | Ok results -> Ok (Results.name_get results)
  | Error e -> Error e

let update t prereqs updates =
  let open Api.Client.Secondary.Update in
  let request, params = Capability.Request.create Params.init_pointer in
  let prereqs =
    Domain_name.Map.fold
      (fun name name_prereq acc ->
        List.fold_left (fun acc prereq -> (name, prereq) :: acc) acc name_prereq)
      prereqs []
  in
  ignore @@ Params.prereqs_set_list params (Update.encode_prereqs prereqs);
  let updates =
    Domain_name.Map.fold
      (fun name name_update acc ->
        List.fold_left (fun acc update -> (name, update) :: acc) acc name_update)
      updates []
  in
  ignore @@ Params.updates_set_list params (Update.encode_updates updates);
  match Capability.call_for_value t method_id request with
  | Ok results -> (
      match Results.success_get results with
      | true -> Ok ()
      | false ->
          let error = Results.error_get results in
          Error (`Remote error))
  | Error e -> Error e
