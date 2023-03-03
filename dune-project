(lang dune 3.4)

(name aeon)

(generate_opam_files true)

(source
 (github RyanGibb/aeon))

(authors "Ryan Gibb")

(maintainers "Ryan Gibb")

(license LICENSE)

(documentation https://url/to/documentation)

(package
 (name aeon)
 (synopsis "")
 (description "")
 (depends (ocaml (>= 5.0.0)) dune eio_main dns (dns-server (>= 6.2.2)) dns-tsig cmdliner logs fmt menhir)
 (tags
  ()))
