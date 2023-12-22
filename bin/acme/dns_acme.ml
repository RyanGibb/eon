(* https://caml.inria.fr/pub/ml-archives/caml-list/2003/07/5ff669a9d2be35ec585b536e2e0fc7ca.xml *)
let protect ~f ~(finally: unit -> unit) =
  let result = ref None in
  try
    result := Some (f ());
    raise Exit
  with
      Exit as e ->
        finally ();
        (match !result with Some x -> x | None -> raise e)
    | e ->
        finally (); raise e

let provision_cert ?account_key ?private_key ~email ~org ~domain prod server_state env =
  let acmeName = ref @@ None in
  let solver =
    let add_record name record =
      let (let*) = Result.bind in

      (* if we've already added a name, just wait
         see end of `add_record`. *)
      if !acmeName != None then (
        Eio.traceln "solving...";
        Ok ()
      ) else 

      (* vertify that the name provided in the ACME server challenge begins with `_acme-challenge` *)
      let verify_name name =
        let labels = Domain_name.to_array name in
        match Array.length labels > 0 && labels.(Array.length labels - 1) = "_acme-challenge" with
        | false -> Error (`Msg "error")
        | true -> Ok ()
      in
      let* _ = verify_name name in

      (* get the nameserver trie *)
      let trie = Dns_server.Primary.data !server_state in

      (* check if there's any issues adding a record for this name *)
      let* trie = match Dns_trie.lookup name Dns.Rr_map.Txt trie with
      (* if there is no record, all is well *)
      | Error `NotFound _ -> Ok trie
      (* if there is a record, let's remove it to be prudent *)
      | Ok (ttl, records) ->
        let trie = Dns_trie.remove_ty name Dns.Rr_map.Txt trie in
        Dns.Rr_map.Txt_set.iter (fun record ->
          Eio.traceln "Clear '%a %ld IN TXT \"%s\"'" Domain_name.pp name ttl record;
        ) records;
        Ok trie;
      (* if there's any other issues, like the server is not authorative for this zone, or the zone has been delegated *)
      | Error e ->
        Eio.traceln "Error with ACME CSR name '%a': %a" Domain_name.pp name Dns_trie.pp_e e;
        let msg = Format.asprintf "%a" Dns_trie.pp_e e in
        Error (`Msg msg)
      in

      (* 1 hour is a sensible TTL *)
      let ttl = 3600l in
      let rr =
        ttl, Dns.Rr_map.Txt_set.singleton record
      in
      let trie = Dns_trie.insert name Dns.Rr_map.Txt rr trie in
      (* TODO send out notifications for secondary nameservers *)
      let new_server_state, _notifications =
        let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
        and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
        Dns_server.Primary.with_data !server_state now ts trie in
      server_state := new_server_state;
      acmeName := Some name;
      Eio.traceln "Create '%a %ld IN TXT \"%s\"'" Domain_name.pp name ttl record;
      (* we could wait for dns propigation here...
         but we hope that a new un-cached record is created
         and if not, the server should retry (RFC 8555 S8.2) *)
      Ok ()
    in
    Letsencrypt_dns.dns_solver add_record
  in

  let endpoint = if prod then Letsencrypt.letsencrypt_production_url else Letsencrypt.letsencrypt_staging_url in
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  protect ~f:(fun () ->
    try
      Tls_le.gen_cert ?account_key ?private_key ~email ~org ~domain ~endpoint ~solver env
    with Tls_le.Le_error msg -> (
        Eio.traceln "ACME error: %s" msg;
        raise (Tls_le.Le_error msg)
    );
  ) ~finally:(fun () ->
    (* once cert provisioned, remove the record *)
    match !acmeName with
    | None -> ()
    | Some name ->
      let trie = Dns_server.Primary.data !server_state in
      match Dns_trie.lookup name Dns.Rr_map.Txt trie with
      | Error e -> Eio.traceln "Error removing %a from trie: %a" Domain_name.pp name Dns_trie.pp_e e;
      | Ok (ttl, records) ->
        let data = Dns_trie.remove_ty name Dns.Rr_map.Txt trie in
        (* TODO send out notifications *)
        let new_server_state, _notifications =
          let now = Ptime.of_float_s @@ Eio.Time.now env#clock |> Option.get
          and ts = Mtime.to_uint64_ns @@ Eio.Time.Mono.now env#mono_clock in
          Dns_server.Primary.with_data !server_state now ts data in
        server_state := new_server_state;
        Dns.Rr_map.Txt_set.iter (fun record ->
          Eio.traceln "Remove '%a %ld IN TXT \"%s\"'" Domain_name.pp name ttl record;
        ) records;
    ()
  )
