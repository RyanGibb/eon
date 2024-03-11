@0xf8f86fb5561e3599;

struct Record {
  name @0 :Text;
  type @1 :Int32;
  value @2 :Text;
}

struct Prereq {
  union {
    exists @0 :Record;
    existsData @1 :Record;
    notExists @2 :Record;
    nameInuse @3 :Record;
    notnameInuse @4 :Record;
  }
}

struct Update {
  union {
    add @0 :Record;
    remove @1 :Record;
    removeAll @2 :Record;
    removeSingle @3 :Record;
  }
}

struct CertReq {
  # Used to request a certificate for a service
  union {
    callback @0 :CertCallback;
    none @1 :Void;
  }
}

interface Zone {
  # Capability to initalize a Zone for which the nameserver is authorative
  init @0 (name :Text) -> (domain :Domain);
}

interface Domain {
  # Capability for a domain

  getName @0 () -> (name :Text);
  # Get the domain name

  delegate @1 (subdomain :Text) -> (domain :Domain);
  # Create a capability for a subdomain

  update @2 (prereqs :List(Prereq), updates :List(Update)) -> ();
  # DNS update

  cert @3 (email: Text, org :Text, subdomain :Text, certCallback :CertCallback) -> ();
  # Request a certificate for a domain ("") / wildcard domain "*"
}

interface CertCallback {
  # Callback to support renewal
  register @0 (success :Bool, error :Text, cert :Data, key :Text) -> ();
}

