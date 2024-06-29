
# Effects-based OCaml Nameserver (EON)

EON is an authoritative nameserver for the Domain Name System (DNS) using the functionally pure [Mirage OCaml-DNS libraries](https://github.com/mirage/ocaml-dns) and [Effects-Based Parallel IO for multicore OCaml](https://github.com/ocaml-multicore/eio), along with some experimental uses of the DNS.

### Quick start

```
$ nix shell github:RyanGibb/eon
$ sudo eon --zonefile <filepath>
```

Or follow the instructions to manually [build from source](#building).

For help:
```
$ eon --help
```

### Building

[Nix](https://nixos.org) can be used to build the project with:

```
$ git clone git@github.com:RyanGibb/eon.git
$ cd eon
$ nix build .
```

The binary can then be found at `result/bin/eon`.

Note that this is using [Nix flakes](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html).

Alternatively, opam and dune tooling can be used:
```
$ opam install .
$ dune build
```

The binary can then be found at `_build/default/src/eon.exe`.

### Running

Once built, to run the project use:

```
$ ./eon --zonefile <filepath>
```

For example:
```
$ ./eon --zonefile examples/example.com
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
$ ./eon --zonefile examples/example.com --log-level 2
```

To operate as a recursive resolver:
```
$ ./eon --zonefile examples/example.com --resolver
```

Which will additionally recursively look up records for domains it is not authoritative over.
Be careful of [DNS amplification attacks](https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/).

### Deployment

A [NixOS module](https://nixos.org/manual/nixos/stable/index.html#sec-writing-modules) is provided that describes a systemd service and some configuration options. See [here](https://www.tweag.io/blog/2020-07-31-nixos-flakes/#adding-modules-from-third-party-flakes) for an example of adding a module from another flake to your NixOS configuration.

It's also possible to simply run this as a binary.

You'll need to configure your zonefile with an [NS](https://www.ietf.org/rfc/rfc1035.html#section-3.3.11) record, and set up a glue record with your registrar to point this domain to the IP that your nameserver is hosted on. See [example.org](./example/example.org) for an example NS record.

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

### Documentation

See [./docs/](./docs/).
