
# Algebraic Effects-based OCaml Naming

Algebraic Effects-based OCaml Naming (AEON) is an implementation of the Domain Name System (DNS) protocol using the functionally pure [Mirage OCaml-DNS libraries](https://github.com/mirage/ocaml-dns) and [Effects-Based Parallel IO for OCaml 5](https://github.com/ocaml-multicore/eio).

The AEON nameserver, `named`, can act as an authoritative nameserver.
The resolver, `resolved`, can do the same in addition to acting as a recursive resolver.

### Quick start

```
$ nix shell github:RyanGibb/aeon
$ sudo named --zonefile <filepath>
```

Or follow the instructions to manually [build from source](#building).

For help:
```
$ named --help
```

### Building

[Nix](https://nixos.org) can be used to build the project with:

```
$ git clone git@github.com:RyanGibb/aeon.git
$ cd aeon
$ nix build .
```

The binary can then be found at `result/bin/named`.

Note that this is using [Nix flakes](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html).

Alternatively, opam and dune tooling can be used:
```
$ opam create switch .
$ opam install
$ dune build
```

The binary can then be found at `_build/default/src/aeon.exe`.

### Running

Once built, to run the project use:

```
$ ./named --zonefile <filepath>
```

For example:
```
$ ./named --zonefile examples/example.com
```

The zonefile format is defined in [RFC1035 Section 5.1](https://datatracker.ietf.org/doc/html/rfc1035#section-5.1), but a minimal example is provided in [example.org](./example/example.org).

Note root access may be required to bind to port 53.

You can then query your nameserver using the [BIND](https://www.isc.org/bind/) `dig` utility:
```
$ dig example.org @localhost +short
203.0.113.0
```

The command line argument `--log-level` can be used to specify a log verbosity e.g.:
```
$ ./named --zonefile examples/example.com --log-level 2
```

The same can be done with `resolved`, except it will additionally recursively look up records for domains it is not authoritative over.
Be careful of [DNS amplification attacks](https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/).

### Deployment

A [NixOS module](https://nixos.org/manual/nixos/stable/index.html#sec-writing-modules) is provided that describes a systemd service and some configuration options. See [here](https://www.tweag.io/blog/2020-07-31-nixos-flakes/#adding-modules-from-third-party-flakes) for an example of adding a module from another flake to your NixOS configuration.

It's also possible to simply run this as a binary.

You'll need to configure your zonefile with an [NS](https://www.ietf.org/rfc/rfc1035.html#section-3.3.11) record, and set up a glue record with your registrar to point this domain to the IP that your nameserver is hosted on. See [example.org](./example/example.org) for an example NS record.

### TSIG Authentication

The server uses [TSIG](https://www.rfc-editor.org/rfc/rfc2845) resources records (RRs) to authenticate queries. For example, [DNS UPDATE](https://www.rfc-editor.org/rfc/rfc2136) queries can be authenticated to provide secure dynamic updates.

We pass [HMAC](https://www.rfc-editor.org/rfc/rfc2104) keys to the server through a zonefile representation that is in a file named `<zonefile>._keys`, e.g. [example.org._keys](./example/example.org._keys). These are secret keys, and should not be published.

A DNSKEY RR domain name in this file must be of the format `<name>.<operation>.<domain>`, where `<operation>` can be `_update`, `_transfer`, or `_notify`.

To generate these keys we can use:
```
$ cat /dev/random | head -c 32 | base64
FGwot7AqiDIthEv6TippJm35DaRpRac5NSLd/wSp9go=
```

Then to perform a dynamic update we can use use the BIND utility `nsupdate`:
```
$ echo "update add test.example.org 86400 A 203.0.113.1\n" | nsupdate -l -y hmac-sha256:client._update.example.org:FGwot7AqiDIthEv6TippJm35DaRpRac5NSLd/wSp9go=
$ dig test.example.org @localhost
203.0.113.1
```

The TSIG key name, `client._update.example.org` here, must match the name in the zonefile.

### Transport

The [transport.ml](src/transport.ml) file contains logic to use DNS as a stream[transport](https://en.wikipedia.org/wiki/Transport_layer`) protocol.
An example application that uses this can be found in [netcat.ml](src/netcat.ml)/[netcatd.ml](src/netcatd.ml).

### Development

While it's possible to continuously rebuild the Nix derivation during development, this is quite slow due to isolated builds. A nice compromise is to use Nix to provide the dependencies but to use an un-sandboxed dune to build the project benefiting from caches and incremental builds.

To do this, use:
```
nix develop . -c dune build
```

Development packages [https://github.com/ocaml/ocaml-lsp](ocaml-lsp) are also provided, so one can launch an editor with:
```
nix develop . -c <your-favourite-editor>
```

Alternatively, opam tooling can be used to provide the development dependencies.
