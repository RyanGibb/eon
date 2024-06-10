open Dns
open Raw

(* TODO come up with a better encoding *)
let encode_data k v =
  let buf = Dns.Rr_map.encode_single k v in
  Cstruct.to_string buf

let type_of_int typ =
  match Rr_map.of_int typ with
  | Ok rr -> rr
  | Error _e ->
      raise (Invalid_argument (Printf.sprintf "Unknown RR type %d" typ))

let decode_data ?(ttl = 0l) typ value =
  let buf = Cstruct.of_string value in
  match Dns.Rr_map.decode_single buf ttl (type_of_int typ) with
  | Ok b -> b
  | Error e -> raise (Invalid_argument (Printf.sprintf "%s" e))

let encode_prereqs prereqs =
  List.map
    (fun (domain, op) ->
      let open Api.Builder in
      let open Packet.Update in
      let prereq = Prereq.init_root () in
      Prereq.name_set prereq (Domain_name.to_string domain);
      (match op with
      | Exists (Rr_map.K typ) ->
          let open Prereq.Exists in
          let exists = Prereq.exists_init prereq in
          type_set_exn exists (Dns.Rr_map.to_int typ)
      | Exists_data (Rr_map.B (typ, v)) ->
          let open Prereq.ExistsData in
          let existsData = Prereq.exists_data_init prereq in
          type_set_exn existsData (Dns.Rr_map.to_int typ);
          value_set existsData (encode_data typ v)
      | Not_exists (Rr_map.K typ) ->
          let open Prereq.NotExists in
          let not_exists = Prereq.not_exists_init prereq in
          type_set_exn not_exists (Dns.Rr_map.to_int typ)
      | Name_inuse -> Prereq.name_in_use_set prereq
      | Not_name_inuse -> Prereq.not_name_in_use_set prereq);
      prereq)
    prereqs

let encode_updates updates =
  List.map
    (fun (domain, op) ->
      let open Api.Builder in
      let open Packet.Update in
      let update = Update.init_root () in
      Update.name_set update (Domain_name.to_string domain);
      (match op with
      | Remove (Rr_map.K typ) ->
          let open Update.Remove in
          let remove = Update.remove_init update in
          type_set_exn remove (Dns.Rr_map.to_int typ)
      | Remove_all -> Update.remove_all_set update
      | Remove_single (Rr_map.B (typ, v)) ->
          let open Update.RemoveSingle in
          let removeSingle = Update.remove_single_init update in
          type_set_exn removeSingle (Dns.Rr_map.to_int typ);
          value_set removeSingle (encode_data typ v)
      | Add (Rr_map.B (typ, v)) ->
          let open Update.Add in
          let add = Update.add_init update in
          type_set_exn add (Dns.Rr_map.to_int typ);
          value_set add (encode_data typ v);
          ttl_set add (Dns.Rr_map.ttl typ v));
      update)
    updates

let add_to_list name a map =
  let base =
    match Domain_name.Map.find name map with None -> [] | Some x -> x
  in
  Domain_name.Map.add name (base @ [ a ]) map

let decode_prereqs domain prereqs =
  Capnp.Array.fold_right
    ~f:(fun prereq map ->
      let open Api.Reader.Prereq in
      let name = Domain_name.of_string_exn (name_get prereq) in
      if not (Domain_name.is_subdomain ~subdomain:name ~domain) then
        raise
          (Invalid_argument
             (Fmt.str "Invalid subdomain %a of %a" Domain_name.pp name
                Domain_name.pp domain));
      match get prereq with
      | Exists exists ->
          add_to_list name
            (Dns.Packet.Update.Exists (type_of_int (Exists.type_get exists)))
            map
      | ExistsData existsData ->
          add_to_list name
            (Dns.Packet.Update.Exists_data
               (decode_data
                  (ExistsData.type_get existsData)
                  (ExistsData.value_get existsData)))
            map
      | NotExists notExists ->
          add_to_list name
            (Dns.Packet.Update.Not_exists
               (type_of_int (NotExists.type_get notExists)))
            map
      | NameInUse -> add_to_list name Dns.Packet.Update.Name_inuse map
      | NotNameInUse -> add_to_list name Dns.Packet.Update.Not_name_inuse map
      | Undefined i ->
          raise (Invalid_argument (Printf.sprintf "Undefined prereq %d" i)))
    ~init:Domain_name.Map.empty prereqs

let decode_updates domain updates =
  Capnp.Array.fold_right
    ~f:(fun update map ->
      let open Api.Reader.Update in
      let name = Domain_name.of_string_exn (name_get update) in
      if not (Domain_name.is_subdomain ~subdomain:name ~domain) then
        raise
          (Invalid_argument
             (Fmt.str "Invalid subdomain %a of %a" Domain_name.pp name
                Domain_name.pp domain));
      match get update with
      | Add add ->
          add_to_list name
            (Dns.Packet.Update.Add
               (decode_data ~ttl:(Add.ttl_get add) (Add.type_get add)
                  (Add.value_get add)))
            map
      | Remove remove ->
          add_to_list name
            (Dns.Packet.Update.Remove (type_of_int (Remove.type_get remove)))
            map
      | RemoveAll -> add_to_list name Dns.Packet.Update.Remove_all map
      | RemoveSingle removeSingle ->
          add_to_list name
            (Dns.Packet.Update.Remove_single
               (decode_data
                  (RemoveSingle.type_get removeSingle)
                  (RemoveSingle.value_get removeSingle)))
            map
      | Undefined i ->
          raise (Invalid_argument (Printf.sprintf "Undefined update %d" i)))
    ~init:Domain_name.Map.empty updates

let update_trie env server_state domain prereqs updates =
  let prereqs = decode_prereqs domain prereqs in
  let updates = decode_updates domain updates in
  Eio.traceln "Domain.update(%a) domain=%s" Dns.Packet.Update.pp
    (prereqs, updates)
    (Domain_name.to_string domain);
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
  | Error rcode ->
      raise
        (Invalid_argument (Fmt.str "Error updating trie %a" Dns.Rcode.pp rcode))
