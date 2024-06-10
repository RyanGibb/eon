open Raw
open Capnp_rpc_lwt

let local sr domain server_state initial_secondaries secondary_dir =
  let module Primary = Api.Service.Primary in
  Persistence.with_sturdy_ref sr Primary.local
  @@ object
       inherit Primary.service
       val secondaries = ref initial_secondaries

       method get_name_impl _params release_param_caps =
         let open Primary.GetName in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         Results.name_set results (Domain_name.to_string domain);
         Service.return response

       method register_seconday_impl params release_param_caps =
         let open Primary.RegisterSeconday in
         let secondary = Params.secondary_get params in
         release_param_caps ();
         Eio.traceln "Primary.registerSecondary() in primary=%a" Domain_name.pp
           domain;
         match secondary with
         | None -> Service.fail "No secondary parameter."
         | Some secondary -> (
             secondaries := secondary :: !secondaries;
             (* save capability to file *)
             let uri = Persistence.save_exn secondary in
             (match
                let _, file =
                  Eio.Path.(secondary_dir / Domain_name.to_string domain)
                in
                Capnp_rpc_unix.Cap_file.save_uri uri file
              with
             | Error (`Msg m) -> failwith m
             | Ok () -> ());

             let trie = Dns_server.Primary.data !server_state in
             match Dns_trie.entries domain trie with
             | Error e ->
                 Eio.traceln "Error looking up entries for %a: %a"
                   Domain_name.pp domain Dns_trie.pp_e e;
                 Service.fail "Error looking up entries"
             | Ok (soa, entries) -> (
                 let updates =
                   Domain_name.Map.map
                     (fun rrmap ->
                       Dns.Rr_map.fold
                         (fun b updates -> Dns.Packet.Update.Add b :: updates)
                         rrmap [])
                     entries
                 in
                 (* add SOA to updates *)
                 let updates =
                   Domain_name.Map.update domain
                     (fun updates ->
                       Some
                         (Dns.Packet.Update.Add Dns.Rr_map.(B (Soa, soa))
                         :: Option.value updates ~default:[]))
                     updates
                 in
                 match
                   Secondary.update secondary Domain_name.Map.empty updates
                 with
                 | Error (`Capnp e) ->
                     Eio.traceln "Error calling Secondary.update %a"
                       Capnp_rpc.Error.pp e;
                     Service.fail "Error transfering zone"
                 | Error (`Remote e) ->
                     Eio.traceln "Remote error: %s" e;
                     Service.fail "Error transfering zone"
                 | Ok () -> Service.return @@ Service.Response.create_empty ()))

       method update_secondaries_impl params release_param_caps =
         let open Primary.UpdateSecondaries in
         let prereqs = Params.prereqs_get params in
         let updates = Params.updates_get params in
         release_param_caps ();
         List.iter
           (fun secondary ->
             let prereqs = Update.decode_prereqs domain prereqs in
             let updates = Update.decode_updates domain updates in
             match Secondary.update secondary prereqs updates with
             | Error (`Capnp e) ->
                 Eio.traceln "Error calling Secondary.update %a"
                   Capnp_rpc.Error.pp e
             | Error (`Remote e) -> Eio.traceln "Remote error: %s" e
             | Ok () -> ())
           !secondaries;
         Service.return_empty ()
     end

let get_name t =
  let open Api.Client.Primary.GetName in
  let request = Capability.Request.create_no_args () in
  match Capability.call_for_value t method_id request with
  | Ok results -> Ok (Results.name_get results)
  | Error e -> Error e

let register_secondary t ~secondary =
  let open Api.Client.Primary.RegisterSeconday in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.secondary_set params (Some secondary);
  Capability.call_for_unit t method_id request

let update_secondaries t prereqs updates =
  let open Api.Client.Primary.UpdateSecondaries in
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
