
let parse_zonefiles ~fs zonefiles =
  let trie, keys = List.fold_left (fun (trie, keys) zonefile ->
    let ( / ) = Eio.Path.( / ) in
    match
      let data = Eio.Path.load @@ fs / zonefile in
      Dns_zone.parse data
    with
    | Error `Msg msg ->
      Format.fprintf Format.std_formatter "ignoring zonefile %s: %s" zonefile msg;
      trie, keys
    | Ok rrs ->
      let keys' =
        try
          let keydata = Eio.Path.load @@ fs / (zonefile ^ "._keys") in
          match Dns_zone.parse keydata with
          | Error `Msg msg ->
            Format.fprintf Format.std_formatter "ignoring zonefile %s: %s" zonefile msg;
            keys
          | Ok rrs ->
            let keys' = Domain_name.Map.fold (fun n data acc ->
              match Dns.Rr_map.(find Dnskey data) with
              | None ->
                Format.fprintf Format.std_formatter "no dnskey found %a" Domain_name.pp n;
                acc
              | Some (_, keys) ->
                match Dns.Rr_map.Dnskey_set.elements keys with
                | [ x ] -> Domain_name.Map.add n x acc
                | xs ->
                  Format.fprintf Format.std_formatter
                  "ignoring %d dnskeys for %a (only one supported)"
                    (List.length xs) Domain_name.pp n;
                  acc)
              rrs Domain_name.Map.empty
            in
            let f key a _b =
              Format.fprintf Format.std_formatter "encountered deplicate key %a"
                Domain_name.pp key;
              Some a
            in
            Domain_name.Map.union f keys keys'
        with
          Eio.Io _ -> keys
      in
      let trie' = Dns_trie.insert_map rrs trie in
      trie', keys')
    (Dns_trie.empty, Domain_name.Map.empty)
    zonefiles in
  let keys = Domain_name.Map.bindings keys in
  trie, keys
