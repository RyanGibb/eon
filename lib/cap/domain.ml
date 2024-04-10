open Raw
open Capnp_rpc_lwt

let read_pem filepath decode_pem =
  try
    match Eio.Path.is_file filepath with
    | true -> Some (Eio.Path.load filepath |> Cstruct.of_string |> decode_pem |> Tls_le.errcheck)
    | false -> None
  with exn ->
    let _fd, path = filepath in
    Format.fprintf Format.err_formatter "error reading %s %a\n" path Eio.Exn.pp exn;
    Format.pp_print_flush Format.err_formatter ();
    None

let write_pem filepath pem =
  try Eio.Path.save ~create:(`Or_truncate 0o600) filepath (pem |> Cstruct.to_string)
  with exn ->
    let _fd, path = filepath in
    Format.fprintf Format.err_formatter "error saving %s %a\n" path Eio.Exn.pp exn;
    Format.pp_print_flush Format.err_formatter ();
    raise (Sys_error "Failed to write to file")

let rec local env domain server_state provision_cert state_dir =
  let account_dir = Eio.Path.(env#fs / state_dir / "accounts") in
  let load_account_key email = read_pem Eio.Path.(account_dir / email / "account.pem") X509.Private_key.decode_pem in
  let save_account_key email key =
    let ( / ) = Eio.Path.( / ) in
    let dir = account_dir / email in
    Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 dir;
    let filepath = dir / "account.pem" in
    write_pem filepath (X509.Private_key.encode_pem key)
  in

  let cert_dir = Eio.Path.(env#fs / state_dir / "certs") in
  let load_private_key domain =
    read_pem Eio.Path.(cert_dir / Domain_name.to_string domain / "privkey.pem") X509.Private_key.decode_pem
  in
  let save_private_key domain key =
    let ( / ) = Eio.Path.( / ) in
    let dir = cert_dir / Domain_name.to_string domain in
    Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 dir;
    let filepath = dir / "privkey.pem" in
    write_pem filepath (X509.Private_key.encode_pem key)
  in

  let load_cert domain =
    read_pem Eio.Path.(cert_dir / Domain_name.to_string domain / "fullcert.pem") X509.Certificate.decode_pem_multiple
  in
  let save_cert domain key =
    let ( / ) = Eio.Path.( / ) in
    let dir = cert_dir / Domain_name.to_string domain in
    Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 dir;
    let filepath = dir / "fullcert.pem" in
    write_pem filepath (X509.Certificate.encode_pem_multiple key)
  in

  let module Domain = Api.Service.Domain in
  Domain.local
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
         let org = Params.org_get params in
         let subdomain = Params.subdomain_get params in
         let mgr = Option.get (Params.cert_callback_get params) in
         release_param_caps ();
         Eio.traceln "Domain.bind(email=%s, org=%s, subdomain=%s) domain=%s" email org subdomain
           (Domain_name.to_string domain);
         let response, _results = Service.Response.create Results.init_pointer in
         let callback_result =
           try
             let domain = Domain_name.append_exn domain (Domain_name.of_string_exn subdomain) in
             let cert, private_key =
               match (load_cert domain, load_private_key domain) with
               (* TODO what if this is out of date *)
               | Some cert, Some private_key -> (cert, private_key)
               (* if we don't have them cached, provision them *)
               | _ ->
                   let cert, account_key, private_key, _csr =
                     provision_cert ?account_key:(load_account_key email) ?private_key:(load_private_key domain) ~email
                       ~org domain
                   in
                   save_account_key email account_key;
                   save_private_key domain private_key;
                   save_cert domain cert;
                   (cert, private_key)
             in
             Cert_callback.register mgr true "" (Some cert) (Some private_key)
           with
           | Tls_le.Le_error msg -> Cert_callback.register mgr false msg None None
           | e ->
               let msg = Printexc.to_string e in
               Cert_callback.register mgr false msg None None
         in
         (match callback_result with Ok () -> () | Error (`Capnp e) -> Eio.traceln "%a" Capnp_rpc.Error.pp e);
         (* TODO register renewal process *)
         Service.return response

       method delegate_impl params release_param_caps =
         let open Domain.Delegate in
         let subdomain = Params.subdomain_get params in
         release_param_caps ();
         Eio.traceln "Service.delegate(subdomain='%s')" subdomain;
         let response, results = Service.Response.create Results.init_pointer in
         (match Domain_name.of_string subdomain with
         | Error (`Msg e) -> Eio.traceln "Domain.delegate error parsing domain: %s" e
         | Ok subdomain ->
             let domain = Domain_name.append_exn domain subdomain in
             Results.domain_set results (Some (local env domain server_state provision_cert state_dir)));
         Service.return response

       method update_impl params release_param_caps =
         let open Domain.Update in
         let prereqs = Params.prereqs_get params in
         let updates = Params.updates_get params in
         release_param_caps ();
         let open Dns in
         let open Api.Reader in
         let type_of_capnp typ =
           match Rr_map.of_string typ with
           | Ok rr -> rr
           | Error _e -> raise (Invalid_argument (Printf.sprintf "Unknown RR type %s" typ))
         in
         let binding_of_capnp ?(ttl = 0l) typ value =
           match Rr_map.of_string typ with
           | Ok (K rr) -> (
               match rr with
               | Cname -> Rr_map.B (Cname, (ttl, Domain_name.of_string_exn value))
               | A -> Rr_map.B (A, (ttl, Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn value)))
               | Aaaa -> Rr_map.B (Aaaa, (ttl, Ipaddr.V6.Set.singleton (Ipaddr.V6.of_string_exn value)))
               | _ -> raise (Invalid_argument (Printf.sprintf "Unsupported RR type %s" typ)))
           | Error _e -> raise (Invalid_argument (Printf.sprintf "Unknown RR type %s" typ))
         in
         let add_to_list name a map =
           let base = match Domain_name.Map.find name map with None -> [] | Some x -> x in
           Domain_name.Map.add name (base @ [ a ]) map
         in
         let response, results = Service.Response.create Results.init_pointer in
         (match
            let prereqs =
              Capnp.Array.fold_right
                ~f:(fun prereq map ->
                  let open Api.Reader.Prereq in
                  let name = Domain_name.of_string_exn (name_get prereq) in
                  match get prereq with
                  | Exists exists ->
                      add_to_list name (Dns.Packet.Update.Exists (type_of_capnp (Exists.type_get exists))) map
                  | ExistsData existsData ->
                      add_to_list name
                        (Dns.Packet.Update.Exists_data
                           (binding_of_capnp (ExistsData.type_get existsData) (ExistsData.value_get existsData)))
                        map
                  | NotExists notExists ->
                      add_to_list name (Dns.Packet.Update.Not_exists (type_of_capnp (NotExists.type_get notExists))) map
                  | NameInUse -> add_to_list name Dns.Packet.Update.Name_inuse map
                  | NotNameInUse -> add_to_list name Dns.Packet.Update.Not_name_inuse map
                  | Undefined i -> raise (Invalid_argument (Printf.sprintf "Undefined prereq %d" i)))
                ~init:Domain_name.Map.empty prereqs
            in
            let updates =
              Capnp.Array.fold_right
                ~f:(fun update map ->
                  let open Api.Reader.Update in
                  let name = Domain_name.of_string_exn (name_get update) in
                  match Update.get update with
                  | Update.Add add ->
                      add_to_list name
                        (Dns.Packet.Update.Add
                           (binding_of_capnp ~ttl:(Add.ttl_get add) (Add.type_get add) (Add.value_get add)))
                        map
                  | Update.Remove remove ->
                      add_to_list name (Dns.Packet.Update.Remove (type_of_capnp (Remove.type_get remove))) map
                  | Update.RemoveAll -> add_to_list name Dns.Packet.Update.Remove_all map
                  | Update.RemoveSingle removeSingle ->
                      add_to_list name
                        (Dns.Packet.Update.Remove_single
                           (binding_of_capnp (RemoveSingle.type_get removeSingle) (RemoveSingle.value_get removeSingle)))
                        map
                  | Undefined i -> raise (Invalid_argument (Printf.sprintf "Undefined update %d" i)))
                ~init:Domain_name.Map.empty updates
            in
            Eio.traceln "Domain.update(%a) domain=%s" Dns.Packet.Update.pp (prereqs, updates) (Domain_name.to_string domain);
            (* TODO locking *)
            let trie = Dns_server.Primary.data !server_state in
            match Dns_server.update_data trie domain (prereqs, updates) with
            | Ok (trie, _) ->
                let new_server_state, _notifications =
                  let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
                  and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
                  Dns_server.Primary.with_data !server_state now ts trie
                in
                server_state := new_server_state
            | Error rcode -> raise (Invalid_argument (Fmt.str "Error updating trie %a" Dns.Rcode.pp rcode))
          with
         | exception e ->
             let msg = Printexc.to_string e in
             Results.success_set results false;
             Results.error_set results msg
         | _ -> Results.success_set results true);
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

module Update = struct
  open Dns
  type prereq =
    | Exists of Dns.Rr_map.k
    | Exists_data of Dns.Rr_map.k * string
    | Not_exists of Dns.Rr_map.k
    | Name_inuse
    | Not_name_inuse

  type update =
    | Remove of Rr_map.k
    | Remove_all
    | Remove_single of Dns.Rr_map.k * string
    | Add of Rr_map.k * string * int32
end

let update t prereqs updates =
  let open Api.Client.Domain.Update in
  let open Update in
  let request, params = Capability.Request.create Params.init_pointer in
  ignore
  @@ Params.prereqs_set_list params
       (List.map
          (fun (domain, op) ->
            let open Api.Builder in
            let prereq = Prereq.init_root () in
            Prereq.name_set prereq (Domain_name.to_string domain);
            (match op with
            | Exists typ ->
                let open Prereq.Exists in
                let exists = Prereq.exists_init prereq in
                type_set exists (Fmt.str "%a" Dns.Rr_map.ppk typ)
            | Exists_data (typ, value) ->
                let open Prereq.ExistsData in
                let existsData = Prereq.exists_data_init prereq in
                type_set existsData (Fmt.str "%a" Dns.Rr_map.ppk typ);
                value_set existsData value
            | Not_exists typ ->
                let open Prereq.NotExists in
                let not_exists = Prereq.not_exists_init prereq in
                type_set not_exists (Fmt.str "%a" Dns.Rr_map.ppk typ)
            | Name_inuse -> Prereq.name_in_use_set prereq
            | Not_name_inuse -> Prereq.not_name_in_use_set prereq);
            prereq)
          prereqs);
  ignore
  @@ Params.updates_set_list params
       (List.map
          (fun (domain, op) ->
            let open Api.Builder in
            let update = Update.init_root () in
            Update.name_set update (Domain_name.to_string domain);
            (match op with
            | Remove typ ->
                let open Update.Remove in
                let remove = Update.remove_init update in
                type_set remove (Fmt.str "%a" Dns.Rr_map.ppk typ)
            | Remove_all -> Update.remove_all_set update
            | Remove_single (typ, value) ->
                let open Update.RemoveSingle in
                let removeSingle = Update.remove_single_init update in
                type_set removeSingle (Fmt.str "%a" Dns.Rr_map.ppk typ);
                value_set removeSingle value
            | Add (typ, value, ttl) ->
                let open Update.Add in
                let add = Update.add_init update in
                type_set add (Fmt.str "%a" Dns.Rr_map.ppk typ);
                value_set add value;
                ttl_set add ttl);
            update)
          updates);
  match Capability.call_for_value t method_id request with
  | Ok results -> (
      match Results.success_get results with
      | true -> Ok ()
      | false ->
          let error = Results.error_get results in
          Error (`Remote error))
  | Error e -> Error e
