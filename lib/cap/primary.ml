open Raw
open Capnp_rpc

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
                (* NB only supports one secondary on a URI *)
                let _, file =
                  Eio.Path.(secondary_dir / ((Uri.host uri |> Option.value ~default:"no-uri") ^ ".cap"))
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
                         (fun b updates ->
                           match b with
                           | B (Mx, (ttl, set)) -> (Dns.Rr_map.Mx_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Mx, (ttl, Dns.Rr_map.Mx_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Txt, (ttl, set)) -> (Dns.Rr_map.Txt_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Txt, (ttl, Dns.Rr_map.Txt_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Srv, (ttl, set)) -> (Dns.Rr_map.Srv_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Srv, (ttl, Dns.Rr_map.Srv_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Dnskey, (ttl, set)) -> (Dns.Rr_map.Dnskey_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Dnskey, (ttl, Dns.Rr_map.Dnskey_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Caa, (ttl, set)) -> (Dns.Rr_map.Caa_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Caa, (ttl, Dns.Rr_map.Caa_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Tlsa, (ttl, set)) -> (Dns.Rr_map.Tlsa_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Tlsa, (ttl, Dns.Rr_map.Tlsa_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Sshfp, (ttl, set)) -> (Dns.Rr_map.Sshfp_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Sshfp, (ttl, Dns.Rr_map.Sshfp_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Ds, (ttl, set)) -> (Dns.Rr_map.Ds_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Ds, (ttl, Dns.Rr_map.Ds_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Rrsig, (ttl, set)) -> (Dns.Rr_map.Rrsig_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Rrsig, (ttl, Dns.Rr_map.Rrsig_set.singleton e))) ] @ acc) set []) @ updates
                           | B (Loc, (ttl, set)) -> (Dns.Rr_map.Loc_set.fold (fun e acc -> [ Dns.Packet.Update.Add (B (Loc, (ttl, Dns.Rr_map.Loc_set.singleton e))) ] @ acc) set []) @ updates
                           | _ -> Dns.Packet.Update.Add b :: updates)
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
         let response, results = Service.Response.create Results.init_pointer in
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
         Results.success_set results true;
         Service.return response
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
