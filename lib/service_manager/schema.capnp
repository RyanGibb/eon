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

enum Proto {
  tcp @0;
  udp @1;
  http3 @2;
}

struct Address {
  union {
    a @0 :Text;
    aaaa @1 :Text;
    bdaddr @2 :Text;
    wifi @3 :Text;
    lora @4 :Text;
    dtmf @5 :Text;
  }
}

struct HostInfo {
  addresses @0 :List(Address);
  arch @1 :Text;
  location @2 :Text;
}

interface HostRegistration {
  register @0 (info: HostInfo) -> (host :Host);
}

interface Process {
    # from https://github.com/patricoferris/hoke/tree/main/src/lib/schema.capnp
    stdout @0 () -> (data :Text);
    stderr @1 () -> (data :Text);
    stdin  @2 (data :Text) -> ();
}

interface Host {
  getInfo @0 () -> (info :HostInfo);
  shell @1 () -> (process: Process);
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

  register @3 (
      subdomain :Text,
      port: UInt16,
      proto :Proto,
      host: Host,
      certReq :CertReq
	) -> ();
  # Register a service at a subdomain
}

interface CertCallback {
  # Callback to support renewal
  register @0 (success :Bool, error :Text, cert :Data, key :Text) -> ();
}

