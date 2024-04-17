
### Capbility Interface

A [schema.capnp](../lib/cap/schema.capnp) defines a [capnproto](https://capnproto.org/) interface to interact with the nameserver.
A server and client are provided in [cap](../bin/cap/cap.ml]) and [capc](../bin/cap/capc.ml]) respectively.

When we run a nameserver it outputs a capability for each domain for which it is authoritative.
```
$ cap -z example.org --capnp-secret-key-file /var/lib/eon/capnp-secret.pem --capnp-listen-address tcp:example.org:7000 --state-dir /var/lib/eon
$ sudo ls /var/lib/eon/caps/
example.org.cap  zone.cap
```

This capability can then be provided to a client.

```
$ capc get-name example.org.cap
example.org
```

The client can create a new capability for a subdomain, which could be passed to a service.
NB this is persisted to disk so it can be referenced across reboots.

```
$ capc delegate example.org.cap test
Wrote capability to test.example.org.cap
$ capc get-name test.example.org.cap
test.example.org
```

We expose a DNS UPDATE semantic-compatible interface over capnptoto (which not shown here can support arbitrarily complex pre-requisites).

```
$ capc update test.example.org.cap -u add:test.example.org:A:128.232.113.136:3600
$ dig test.example.org +short
128.232.113.136
```

And finally, we also support provisioning TLS certificates with the ACME DNS-01 challenge client embedded in the nameserver, modifying the trie in-memory.
A schema compatible capnproto server could also do this via DNS UPDATES to another DNS provider.

```
$ capc cert test.example.org.cap ryan@test.example.org -d test.example.org
Updated certificate for test.example.org
```

Renewals are supported via forking a fiber, sleeping to the expiration date minus 30 days, and providing the new certificate to the client via a callback.

