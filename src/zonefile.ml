let parse_zonefiles ~fs zonefiles =
  let trie, keys =
    List.fold_left
      (fun (trie, keys) zonefile ->
        match (Eio.Path.load @@ Eio.Path.(fs / zonefile)) |> Dns_zone.parse with
        | Error (`Msg msg) ->
            Format.fprintf Format.std_formatter "ignoring zonefile %s: %s\n"
              zonefile msg;
            (trie, keys)
        | Ok rrs ->
            let keys' =
              try
                match
                  (Eio.Path.load @@ Eio.Path.(fs / (zonefile ^ "._keys")))
                  |> Dns_zone.parse
                with
                | Error (`Msg msg) ->
                    Format.fprintf Format.std_formatter
                      "ignoring zonefile %s: %s\n" zonefile msg;
                    keys
                | Ok rrs ->
                    let keys' =
                      Domain_name.Map.fold
                        (fun n data acc ->
                          match Dns.Rr_map.(find Dnskey data) with
                          | None ->
                              Format.fprintf Format.std_formatter
                                "no dnskey found %a\n" Domain_name.pp n;
                              acc
                          | Some (_, keys) -> (
                              match Dns.Rr_map.Dnskey_set.elements keys with
                              | [ x ] -> Domain_name.Map.add n x acc
                              | xs ->
                                  Format.fprintf Format.std_formatter
                                    "ignoring %d dnskeys for %a (only one \
                                     supported)\n"
                                    (List.length xs) Domain_name.pp n;
                                  acc))
                        rrs Domain_name.Map.empty
                    in
                    let f key a _b =
                      Format.fprintf Format.std_formatter
                        "encountered deplicate key %a\n" Domain_name.pp key;
                      Some a
                    in
                    Domain_name.Map.union f keys keys'
              with Eio.Io _ -> keys
            in
            let trie' = Dns_trie.insert_map rrs trie in
            (trie', keys'))
      (Dns_trie.empty, Domain_name.Map.empty)
      zonefiles
  in
  let keys = Domain_name.Map.bindings keys in
  (trie, keys)
