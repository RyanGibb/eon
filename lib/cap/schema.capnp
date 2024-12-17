@0xf8f86fb5561e3599;

struct Prereq {
  name @0: Text;
  union {
    exists :group {
      type @1 :Int16;
    }
    existsData :group {
      type @2 :Int16;
      value @3 :Data;
    }
    notExists :group {
      type @4 :Int16;
    }
    nameInUse @5 :Void;
    notNameInUse @6 :Void;
  }
}

struct Update {
  name @0: Text;
  union {
    add :group {
      type @1 :Int16;
      value @2 :Data;
	  ttl @3 :Int32;
    }
    remove :group {
      type @4 :Int16;
    }
    removeAll @5 :Void;
    removeSingle :group {
      type @6 :Int16;
      value @7 :Data;
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

interface Domain {
  # Capability for a domain

  getName @0 () -> (name :Text);
  # Get the domain name

  delegate @1 (subdomain :Text) -> (domain :Domain);
  # Create a capability for a subdomain

  update @2 (prereqs :List(Prereq), updates :List(Update)) -> (success :Bool, error :Text);
  # DNS update

  cert @3 (email: Text, domains :List(Text), org :Text, certCallback :CertCallback) -> ();
  # Request a certificate for a domain ("") / wildcard domain "*"
}

interface Primary {
  # Capability for a primary nameserver for a domain

  getName @0 () -> (name :Text);
  # Get the domain name that this primary is serving

  registerSeconday @1 (secondary :Secondary) -> ();
  # register a secondary server with this primary
  # as an optimisation we could add a serial number here

  updateSecondaries @2 (prereqs :List(Prereq), updates :List(Update)) -> (success :Bool, error :Text);
  # update secondary nameservers for this primary
}

interface Secondary {
  # Capability for a secondary nameserver for a domain

  getName @0 () -> (name :Text);
  # Get the domain name that this secondary is serving

  update @1 (prereqs :List(Prereq), updates :List(Update)) -> (success :Bool, error :Text);
  # DNS update from primary
}

interface CertCallback {
  # Callback to support provisioning and renewal

  register @0 (success :Bool, error :Text, cert :Data, key :Text, renewed: Bool) -> ();
  # register a provisioned certificate
}

struct HostInfo {
  name @0 :Text;
}

interface Process {
  stdout @0 () -> (data :Text);
  stderr @1 () -> (data :Text);
  stdin  @2 (data :Text) -> ();
  # from https://github.com/patricoferris/hoke/tree/main/src/lib/schema.capnp
}

struct MoshConnect {
  ip @0 :Text;
  port @1 :Int32;
  key @2 :Data;
}

struct ExitStatus {
  union {
    exited :group {
	  code @0 :Int32;
    }
    signaled :group {
	  code @1 :Int32;
    }
    stopped :group {
	  code @2 :Int32;
    }
  }
}

interface ExitCallback {
  exitStatus @0 (exitStatus: ExitStatus) -> ();
}

interface Host {
  getInfo @0 () -> (info :HostInfo);
  shell @1 (exitCallback :ExitCallback) -> (process :Process);
  mosh @2 () -> (moshConnect :MoshConnect);
}

