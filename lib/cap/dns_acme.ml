exception Dns_acme_error of string

(* https://caml.inria.fr/pub/ml-archives/caml-list/2003/07/5ff669a9d2be35ec585b536e2e0fc7ca.xml *)
let protect ~f ~(finally : unit -> unit) =
  let result = ref None in
  try
    result := Some (f ());
    raise Exit
  with
  | Exit as e -> (
      finally ();
      match !result with Some x -> x | None -> raise e)
  | e ->
      finally ();
      raise e

let provision_cert prod endpoint server_state update env ?account_key
    ?private_key ~email ?(org = None) domains =
  List.iter
    (fun domain ->
      (* check if there's any issues with the domain *)
      match
        let trie = Dns_server.Primary.data !server_state in
        Dns_trie.lookup domain Dns.Rr_map.Txt trie
      with
      (* if there is no record, all is well *)
      | Error (`NotFound _) -> ()
      | Error (`EmptyNonTerminal _) -> ()
      (* if there is a record, we can ignore it *)
      | Ok _ -> ()
      (* if there's any other issues, like the server is not authorative for this zone, or the zone has been delegated *)
      | Error e ->
          let msg = Format.asprintf "%a" Dns_trie.pp_e e in
          raise (Dns_acme_error msg))
    domains;

  let acmeName = ref @@ None in
  let solver =
    let add_record name record =
      let ( let* ) = Result.bind in

      (* if we've already added a name, just wait
         see end of `add_record`. *)
      if !acmeName != None then (
        Eio.traceln "solving...";
        Ok ())
      else
        (* vertify that the name provided in the ACME server challenge begins with `_acme-challenge` *)
        let verify_name name =
          let labels = Domain_name.to_array name in
          match
            Array.length labels > 0
            && labels.(Array.length labels - 1) = "_acme-challenge"
          with
          | false -> Error (`Msg "error")
          | true -> Ok ()
        in
        let* _ = verify_name name in
        acmeName := Some name;

        (* check if there's any issues adding a record for this name *)
        let* () =
          (* get the nameserver trie *)
          let trie = Dns_server.Primary.data !server_state in
          match Dns_trie.lookup name Dns.Rr_map.Txt trie with
          (* if there is no record, all is well *)
          | Error (`NotFound _) -> Ok ()
          (* if there is a record, we'll remove it *)
          | Ok (_ttl, _records) -> Ok ()
          (* if there's any other issues, like the server is not authorative for this zone, or the zone has been delegated *)
          | Error e ->
              Eio.traceln "Error with ACME CSR name '%a': %a" Domain_name.pp
                name Dns_trie.pp_e e;
              let msg = Format.asprintf "%a" Dns_trie.pp_e e in
              Error (`Msg msg)
        in

        (* 1 hour is a sensible TTL *)
        let record_ttl = 3600l in
        let* () =
          match
            update Domain_name.Map.empty
              (Domain_name.Map.singleton name
                 [
                   Dns.(Packet.Update.Remove (Rr_map.K Txt));
                   Dns.(
                     Packet.Update.Add
                       Rr_map.(B (Txt, (record_ttl, Txt_set.singleton record))));
                 ])
          with
          | exception Invalid_argument msg -> Error (`Msg msg)
          | exception e ->
              let msg = Printexc.to_string e in
              Error (`Msg msg)
          | Error (`Capnp e) ->
              Eio.traceln "Error calling Primary.update_secondaries: %a"
                Capnp_rpc.Error.pp e;
              (* we assume secondaries are down *)
              Ok ()
          | Error (`Remote e) ->
              Eio.traceln "Error calling Primary.update_secondaries: %s" e;
              (* we assume secondaries are down *)
              Ok ()
          | Ok () -> Ok ()
        in
        Eio.traceln "Create '%a %ld IN TXT \"%s\"'" Domain_name.pp name
          record_ttl record;
        (* a new, un-cached, record will most likely be created,
           and if not, the ACME server should retry (RFC 8555 S8.2) *)
        Ok ()
    in
    Letsencrypt_dns.dns_solver add_record
  in

  let endpoint =
    match endpoint with
    | Some e -> e
    | None ->
        if prod then Letsencrypt.letsencrypt_production_url
        else Letsencrypt.letsencrypt_staging_url
  in
  protect
    ~f:(fun () ->
      try
        Tls_le.gen_cert ?account_key ?private_key ~email ~org domains ~endpoint
          ~solver env
      with Tls_le.Le_error msg ->
        Eio.traceln "ACME error: %s" msg;
        raise (Tls_le.Le_error msg))
    ~finally:(fun () ->
      (* once cert provisioned, remove the record *)
      match !acmeName with
      | None -> ()
      | Some name ->
          (match
             update Domain_name.Map.empty
               (Domain_name.Map.singleton name
                  [ Dns.(Packet.Update.Remove (Rr_map.K Txt)) ])
           with
          | exception Invalid_argument msg ->
              Eio.traceln "Error removing ACME record: %s" msg
          | exception e ->
              let msg = Printexc.to_string e in
              Eio.traceln "Error removing ACME record: %s" msg
          | Error (`Capnp e) ->
              Eio.traceln
                "Error removing ACME record calling \
                 Primary.update_secondaries: %a"
                Capnp_rpc.Error.pp e
          | Error (`Remote e) ->
              Eio.traceln
                "Error removing ACME record calling \
                 Primary.update_secondaries: %s"
                e
          | Ok () -> ());
          Eio.traceln "Remove '%a TXT" Domain_name.pp name;
          ())
