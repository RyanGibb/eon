@0xf8f86fb5561e3599;

# Root capability
interface Root {
  bind @0 (domain_name :Text) -> (domain :Domain);
}

# Capability for a domain
interface Domain {
  # Request a certificate for a domain ("") / wildcard domain "*" / subdomain
  cert @0 (email: Text, org :Text, subdomain :Text, mgr :CertManager) -> ();
  # DNS update
  # update @1 (subdomain :Text, ttl: Int32, class: Text, type :Text, rdata :Text);
}

# Callback to support renewal
interface CertManager {
  register @0 (success :Bool, error :Text, cert :Data, key :Text) -> ();
}
