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
 (depends (ocaml (>= 5.0.0)) dune eio_main dns (dns-server (>= 6.2.2)) dns-tsig cmdliner aeon-log aeon-zonefile logs fmt menhir)
 (tags
  ()))

(package
 (name aeon-log)
 (depends (ocaml (>= 5.0.0)) dune eio_main dns))

(package
 (name aeon-zonefile)
 (depends (ocaml (>= 5.0.0)) dune eio_main dns dns-server))
