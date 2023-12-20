# [let's encrypt](https://letsencrypt.org/) - an ACME implementation in OCaml

This package contains an implementation of the ACME protocol (mostly client
side) purely in OCaml based on [RFC 8555](https://tools.ietf.org/html/rfc8555).
The HTTP, DNS, and [ALPN](https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-07)
challenges are implemented.

Build with:

    $ opam install letsencrypt
    $ opam install letsencrypt-app #for oacmel, the LE client binary

Generate a new account key with:

    $ openssl req -newkey rsa > csr.pem
    $ openssl genrsa > account.pem

with OCaml version ≥ 4.07.0.
Note: acme.ml is not tested, and should be considered yet to be implemented.
