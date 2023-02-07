(lang dune 3.4)

(name dns-server-eio)

(generate_opam_files true)

(source
 (github RyanGibb/ocaml-dns-eio))

(authors "Ryan Gibb")

(maintainers "Ryan Gibb")

(license LICENSE)

(documentation https://url/to/documentation)

(package
 (name dns-server-eio)
 (synopsis "")
 (description "")
 (depends (ocaml (>= 5.0.0)) dune eio_main dns (dns-server (>= 6.2.2)))
 (tags
  ()))
