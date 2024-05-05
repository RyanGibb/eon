@0xf8f86fb5561e3599;

struct Prereq {
  name @0: Text;
  union {
    exists :group {
      type @1 :Text;
    }
    existsData :group {
      type @2 :Text;
      value @3 :Text;
    }
    notExists :group {
      type @4 :Text;
    }
    nameInUse @5 :Void;
    notNameInUse @6 :Void;
  }
}

struct Update {
  name @0: Text;
  union {
    add :group {
      type @1 :Text;
      value @2 :Text;
	  ttl @3 :Int32;
    }
    remove :group {
      type @4 :Text;
    }
    removeAll @5 :Void;
    removeSingle :group {
      type @6 :Text;
      value @7 :Text;
    }
  }
}

interface UpdateCap {
  update @0 (prereqs :List(Prereq), updates :List(Update)) -> (success :Bool, error :Text);
  # DNS update
}

struct CertReq {
  # Used to request a certificate for a service
  union {
    callback @0 :CertCallback;
    none @1 :Void;
  }
}

interface CertCallback {
  # Callback to support renewal
  register @0 (success :Bool, error :Text, cert :Data, key :Text, renewed: Bool) -> ();
}

struct HostStatus {
  load @0 :Float64;
  carbonIntensity @1 :Float64;
  location :group {
    lat @2 :Float64;
    long @3 :Float64;
  }
}

interface Host {
  getFqdn @0 () -> (fqdn :Text);
  # Get the fully qualified domain name for the host

  getUpdateCap @1 () -> (updateCap: UpdateCap);
  # DNS update capability

  status @2 (status :HostStatus) -> ();
}

interface Domain {
  # Capability for a domain

  getName @0 () -> (name :Text);
  # Get the domain name

  delegate @1 (subdomain :Text) -> (domain :Domain);
  # Create a capability for a subdomain

  getUpdateCap @2 () -> (updateCap :UpdateCap);
  # DNS update capability

  cert @3 (email: Text, domains :List(Text), org :Text, certCallback :CertCallback) -> ();
  # Request a certificate for a domain ("") / wildcard domain "*"

  host @4 (name :Text) -> (host :Host);
  # Create a capability for a host
}

interface Zone {
  # Capability to initalize a Zone for which the nameserver is authorative
  init @0 (name :Text) -> (domain :Domain);
}

