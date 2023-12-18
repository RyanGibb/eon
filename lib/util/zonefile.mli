val parse_zonefiles :
  fs:_ Eio.Path.t ->
  string list ->
  Dns_trie.t * ([ `raw ] Domain_name.t * Dns.Dnskey.t) list
