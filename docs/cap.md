
### Capability Interface

A [schema.capnp](../lib/cap/schema.capnp) defines a [capnproto](https://capnproto.org/) interface to interact with the nameserver.
A server and client are provided in [cap](../bin/cap/cap.ml]) and [capc](../bin/cap/capc.ml]) respectively.

### Running

When we run a nameserver it outputs a domain capability and primary capability for each domain name for which it is authoritative.

```
$ capd -z example.org --capnp-secret-key-file /var/lib/eon/capnp-secret.pem --capnp-listen-address tcp:example.org:7000 --state-dir /var/lib/eon
$ sudo find /var/lib/eon/caps/ -type f
/var/lib/eon/caps/domain/example.org.cap
/var/lib/eon/caps/primary/example.org.cap
```

### Client Operations

A domain capability is used by the `capc` client.
A simple example is using the `getName` method:

```
$ capc get-name example.org.cap
example.org
```

The client can create a new capability for a subdomain with the 'delegate' method.
Note this is persisted to disk, so it can be referenced across restarts.

```
$ capc delegate example.org.cap test
Wrote capability to test.example.org.cap
$ capc get-name test.example.org.cap
test.example.org
```

We expose a DNS UPDATE semantic-compatible interface over Cap'N Proto, which can support arbitrarily complex pre-requisites.

```
$ capc update test.example.org.cap -u add:test.example.org:A:128.232.113.136:3600
$ dig test.example.org +short
128.232.113.136
```

We also support provisioning TLS certificates with the ACME DNS-01 challenge client embedded in the nameserver, modifying the trie in-memory.

```
$ capc cert test.example.org.cap ryan@test.example.org -d test.example.org
Updated certificate for test.example.org
```

Renewals are supported via forking a fiber, sleeping to the expiration date minus 30 days, and providing the new certificate to the client via a callback.

### Secondary Nameserver

We can start a `capd` nameserver with a primary capability from another `capd` nameserver.
The former will act as a secondary nameserver for the capability's domain, assuming the necessary `ns` records are added to the zone.
For example, we could pass a primary capability for `example.org` to `example.com`, adding `example.org. 3600 IN NS ns.example.com.` to `example.org`'s zone, and if the `example.org` nameserver goes down `example.com` will keep serving it.

This works by creating a secondary capability for each primary passed, and registering the secondary capability with the associated primary capability.
The `capd` server will then send the initial zone to the secondary using the `Secondary.update` method.
Updates done with the `Domain.update` method are propagated to all the primary's secondaries using `Secondary.update` as well.

This allows zone's with secondary nameserver to provision certificates by propagating the ACME DNS-01 challenge token to all secondaries.

Capabilities are persisted so if either nameserver goes down, the session will resume upon restart.
We could keep track of the serial number as an optimization to reduce the size of the initial zone transfer.

An example of using a primary capability, received from e.g. `/var/lib/eon/caps/primary/example.org.cap`, is:

```
$ capd -z example.org --capnp-secret-key-file /var/lib/eon/capnp-secret.pem --capnp-listen-address tcp:example.com:7000 --state-dir /var/lib/eon --primary /run/eon/primary/example.org.cap
$ sudo find /var/lib/eon/caps/ -type f
/var/lib/eon/caps/domain/example.com.cap
/var/lib/eon/caps/secondary/example.org/example.org.cap
/var/lib/eon/caps/primary/example.com.cap
```

