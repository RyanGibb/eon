
val parse_zonefiles :
  fs:#Eio.Fs.dir Eio.Path.t ->
  string list -> Dns_trie.t * (Domain_name.Map.key * Dns.Dnskey.t) list
