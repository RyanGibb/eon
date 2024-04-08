open Raw
open Capnp_rpc_lwt

let rec local env domain server_state provision_cert =
  let module Domain = Api.Service.Domain in
  Domain.local
  @@ object
       inherit Domain.service
       val account_key_r = ref @@ None
       val private_key_r = ref @@ None

       method get_name_impl _params release_param_caps =
         let open Domain.GetName in
         release_param_caps ();
         let response, results = Service.Response.create Results.init_pointer in
         Results.name_set results (Domain_name.to_string domain);
         Service.return response

       method cert_impl params release_param_caps =
         let open Domain.Cert in
         let email = Params.email_get params in
         let org = Params.org_get params in
         let subdomain = Params.subdomain_get params in
         let mgr = Option.get (Params.cert_callback_get params) in
         release_param_caps ();
         Eio.traceln "Domain.bind(email=%s, org=%s, subdomain=%s) domain=%s"
           email org subdomain
           (Domain_name.to_string domain);
         let response, _results =
           Service.Response.create Results.init_pointer
         in
         let callback_result =
           try
             let domain =
               Domain_name.append_exn domain
                 (Domain_name.of_string_exn subdomain)
             in
             let cert, account_key, private_key, _csr =
               provision_cert ?account_key:!account_key_r
                 ?private_key:!private_key_r ~email ~org domain
             in
             account_key_r := Some account_key;
             private_key_r := Some private_key;
             Cert_callback.register mgr true "" (Some cert) (Some private_key)
           with
           | Tls_le.Le_error msg ->
               Cert_callback.register mgr false msg None None
           | e ->
               let msg = Printexc.to_string e in
               Cert_callback.register mgr false msg None None
         in
         (match callback_result with
         | Ok () -> ()
         | Error (`Capnp e) -> Eio.traceln "%a" Capnp_rpc.Error.pp e);
         (* TODO register renewal process *)
         Service.return response

       method delegate_impl params release_param_caps =
         let open Domain.Delegate in
         let subdomain = Params.subdomain_get params in
         release_param_caps ();
         Eio.traceln "Service.delegate(subdomain='%s')" subdomain;
         let response, results = Service.Response.create Results.init_pointer in
         (match Domain_name.of_string subdomain with
         | Error (`Msg e) ->
             Eio.traceln "Domain.delegate error parsing domain: %s" e
         | Ok subdomain ->
             let domain = Domain_name.append_exn domain subdomain in
             Results.domain_set results
               (Some (local env domain server_state provision_cert)));
         Service.return response

       method update_impl params release_param_caps =
         let open Domain.Update in
         let prereqs = Params.prereqs_get params in
         let updates = Params.updates_get params in
         release_param_caps ();
         let open Dns in
         let open Api.Reader in
         let record_type_of_capnp record =
           match Rr_map.of_string (Record.type_get record) with
           | Ok rr -> rr
           (* TODO proper error handling *)
           | Error _e -> raise Exit
         in
         let name_of_capnp record =
           Domain_name.of_string_exn @@ Record.name_get record
         in

         let record_of_capnp record =
           match Rr_map.of_string (Record.type_get record) with
             | Ok K rr ->
               let value = Record.value_get record in
               (match rr with
                 | Cname -> Rr_map.(B (Cname, (Record.ttl_get record, Domain_name.of_string_exn value)))
                 | A -> Rr_map.(B (A, (Record.ttl_get record, Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn value))));
                 | Aaaa -> Rr_map.(B (Aaaa, (Record.ttl_get record, Ipaddr.V6.Set.singleton (Ipaddr.V6.of_string_exn value))));
                 (* TODO more rr types *)
                 | _ -> raise Exit)
             (* TODO proper error handling *)
             | Error _e -> raise Exit
         in
         let add_to_list name a map =
           let base = match Domain_name.Map.find name map with None -> [] | Some x -> x in
           Domain_name.Map.add name (base @ [a]) map
         in
         let prereqs = Capnp.Array.fold_right
              ~f:(fun prereq map ->
                let open Api.Reader in
                match Prereq.get prereq with
                | Prereq.Exists record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Exists (record_type_of_capnp record)) map
                | Prereq.ExistsData record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Exists_data (record_of_capnp record)) map
                | Prereq.NotExists record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Not_exists (record_type_of_capnp record)) map
                | Prereq.NameInUse record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Name_inuse) map
                | Prereq.NotNameInUse record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Not_name_inuse) map
                (* TODO proper error handling *)
                | Prereq.Undefined _ -> raise Exit
              )
              ~init:Domain_name.Map.empty
              prereqs in
         let updates = Capnp.Array.fold_right
              ~f:(fun update map ->
                let open Api.Reader in
                match Update.get update with
                | Update.Add record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Add (record_of_capnp record)) map
                | Update.Remove record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Remove (record_type_of_capnp record)) map
                | Update.RemoveAll record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Remove_all) map
                | Update.RemoveSingle record -> add_to_list (name_of_capnp record) (Dns.Packet.Update.Remove_single (record_of_capnp record)) map
                (* TODO proper error handling *)
                | Update.Undefined _ -> raise Exit
              )
              ~init:Domain_name.Map.empty
              updates in
         (* TODO locking *)
         let trie = Dns_server.Primary.data !server_state in
         (match Dns_server.update_data trie domain (prereqs, updates) with
         | Ok (trie, _) ->
           let new_server_state, _notifications =
             let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
             and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
             Dns_server.Primary.with_data !server_state now ts trie
           in
           server_state := new_server_state
          (* TODO proper error handling *)
         | Error _rcode -> raise Exit);
         let response, _results =
           Service.Response.create Results.init_pointer
         in
         Service.return response
     end

let cert t ~email ~org ~subdomain cert_callback =
  let open Api.Client.Domain.Cert in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.email_set params email;
  Params.org_set params org;
  Params.subdomain_set params (Domain_name.to_string subdomain);
  Params.cert_callback_set params (Some cert_callback);
  Capability.call_for_unit t method_id request

let delegate t domain =
  let open Api.Client.Domain.Delegate in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.subdomain_set params (Domain_name.to_string domain);
  Capability.call_for_caps t method_id request Results.domain_get_pipelined

