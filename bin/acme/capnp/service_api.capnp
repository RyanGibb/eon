@0xf8f86fb5561e3599;

# Capability to create an Apex domain
interface Apex {
  create @0 (name: Text) -> (domain :Domain);
}

# Capability for a domain
interface Domain {
  # Create a capability for a subdomain
  delegate @0 (subdomain:Text) -> (domain :Domain);
  # Request a certificate for a domain ("") / wildcard domain "*"
  cert @1 (email: Text, org :Text, subdomain :Text, mgr :CertManager) -> ();
  # DNS update
  # update @2 (subdomain :Text, ttl: Int32, class: Text, type :Text, rdata :Text);
}

# Callback to support renewal
interface CertManager {
  register @0 (success :Bool, error :Text, cert :Data, key :Text) -> ();
}
