(* (c) 2019 Hannes Mehnert, all rights reserved *)

(* goal is to check a given zonefile whether it is valid (and to-be-used
   by an authoritative NS - i.e. there must be a SOA record, TTL are good)
   if a NS/MX name is within the zone, it needs an address record
   the name of the file is taken as the domain name *)
open Dns

let ( let* ) = Result.bind

let load_zone zone =
  let* data = Bos.OS.File.read Fpath.(v zone) in
  let* rrs = Dns_zone.parse data in
  let domain = Domain_name.of_string_exn Fpath.(basename (v zone)) in
  let bad = Domain_name.Map.filter
      (fun name _ -> not (Domain_name.is_subdomain ~domain ~subdomain:name))
      rrs
  in
  if not (Domain_name.Map.is_empty bad) then
    Error (`Msg (Fmt.str "Entries of domain '%a' are not in its zone, won't handle this:@.%a"
                   Domain_name.pp domain Dns.Name_rr_map.pp bad))
  else
    Ok (Dns_trie.insert_map rrs Dns_trie.empty)

let jump _ zone old =
  let* trie = load_zone zone in
  let* () =
    Result.map_error
      (fun e -> `Msg (Fmt.to_to_string Dns_trie.pp_zone_check e))
      (Dns_trie.check trie)
  in
  Logs.app (fun m -> m "successfully checked zone") ;
  let zones =
    Dns_trie.fold Soa trie
      (fun name _ acc -> Domain_name.Set.add name acc)
      Domain_name.Set.empty
  in
  if Domain_name.Set.cardinal zones = 1 then
    let zone = Domain_name.Set.choose zones in
    let* zone_data = Dns_server.text zone trie in
    Logs.debug (fun m -> m "assembled zone data %s" zone_data) ;
    (match old with
     | None -> Ok ()
     | Some fn ->
       let* old = load_zone fn in
       match Dns_trie.lookup zone Soa trie, Dns_trie.lookup zone Soa old with
       | Ok fresh, Ok old when Soa.newer ~old fresh ->
         Logs.debug (fun m -> m "zone %a newer than old" Domain_name.pp zone) ;
         Ok ()
       | _ ->
         Error (`Msg "SOA comparison wrong"))
  else
    Error (`Msg "expected exactly one zone")

open Cmdliner

let newzone =
  let doc = "New zone file" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"ZONE")

let oldzone =
  let doc = "Old zone file" in
  Arg.(value & opt (some file) None & info [ "old" ] ~doc ~docv:"ZONE")

let cmd =
  let term =
    Term.(term_result (const jump $ Dns_cli.setup_log $ newzone $ oldzone))
  and info = Cmd.info "ozone" ~version:"%%VERSION_NUM%%"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
