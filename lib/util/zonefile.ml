let parse_keys keyfile filename prev_keys =
  try
    match Eio.Path.load keyfile |> Dns_zone.parse with
    | Error (`Msg msg) ->
        Format.fprintf Format.err_formatter "ignoring keyfile %s: %s\n" filename
          msg;
        Format.pp_print_flush Format.err_formatter ();
        prev_keys
    | Ok rrs ->
        let keys' =
          (* From Dns_zone.decode_keys *)
          Domain_name.Map.fold
            (fun n data acc ->
              match Dns.Rr_map.(find Dnskey data) with
              | None ->
                  Format.fprintf Format.err_formatter
                    "while parsing keyfile %s no dnskey found %a\n" filename
                    Domain_name.pp n;
                  Format.pp_print_flush Format.err_formatter ();
                  acc
              | Some (_, keys) -> (
                  match Dns.Rr_map.Dnskey_set.elements keys with
                  | [ x ] -> Domain_name.Map.add n x acc
                  | xs ->
                      Format.fprintf Format.err_formatter
                        "while parsing keyfile %s ignoring %d dnskeys for %a \
                         (only one supported)\n"
                        filename (List.length xs) Domain_name.pp n;
                      Format.pp_print_flush Format.err_formatter ();
                      acc))
            rrs Domain_name.Map.empty
        in
        let f key a _b =
          Format.fprintf Format.err_formatter
            "while parsing keyfile %s encountered deplicate key %a\n" filename
            Domain_name.pp key;
          Format.pp_print_flush Format.err_formatter ();
          Some a
        in
        Domain_name.Map.union f prev_keys keys'
  with
  | Eio.Io (Eio.Fs.E (Eio.Fs.Not_found _), _) -> prev_keys
  | exn ->
      Format.fprintf Format.err_formatter "error parsing keyfile: %a\n"
        Eio.Exn.pp exn;
      Format.pp_print_flush Format.err_formatter ();
      prev_keys

let parse_zonefiles ~fs zonefiles =
  let trie, keys =
    List.fold_left
      (fun (prev_trie, prev_keys) zonefile ->
        match (Eio.Path.load @@ Eio.Path.(fs / zonefile)) |> Dns_zone.parse with
        | Error (`Msg msg) ->
            Format.fprintf Format.err_formatter "ignoring zonefile %s: %s\n"
              zonefile msg;
            Format.pp_print_flush Format.err_formatter ();
            (prev_trie, prev_keys)
        | Ok rrs ->
            let keys =
              let filename = zonefile ^ "._keys" in
              parse_keys Eio.Path.(fs / filename) filename prev_keys
            in
            let trie = Dns_trie.insert_map rrs prev_trie in
            (trie, keys))
      (Dns_trie.empty, Domain_name.Map.empty)
      zonefiles
  in
  (trie, Domain_name.Map.bindings keys)
