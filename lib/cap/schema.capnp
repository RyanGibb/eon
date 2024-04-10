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

  update @2 (prereqs :List(Prereq), updates :List(Update)) -> (success :Bool, error :Text);
  # DNS update

  cert @3 (email: Text, org :Text, subdomain :Text, certCallback :CertCallback) -> ();
  # Request a certificate for a domain ("") / wildcard domain "*"
}

interface CertCallback {
  # Callback to support renewal
  register @0 (success :Bool, error :Text, cert :Data, key :Text) -> ();
}

