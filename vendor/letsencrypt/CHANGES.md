# v0.4.1 (2021-10-27)

* remove rresult dependency (#29 @hannesm)
* avoid deprecated fmt functions (#29 @hannesm)

# v0.4.0 (2021-09-21)

* support EC (P-256, P-384, P-521) account keys (@reynir @hannesm)
  (reported in #24 by @dinosaure)
* allow key_type to be passed into the alpn_solver (@hannesm)
* add RFC 7520 test cases (@reynir @hannesm)
* remove astring dependency (@hannesm)
* bugfix: "orders" field in account is Uri.t option, not a list (@hannesm)
  (reported in #27 by @torinnd)

# v0.3.0 (2021-07-19)

Reduce dependency cone (#26, @dinosaure & @hannesm)
- remove cohttp dependency, provide a HTTP_client module type
- provide letsencrypt-dns with dns solver
- provide letsencrypt-app for the client binary

# v0.2.5 (2021-04-22)

* adapt to X.509 0.13.0 API (@hannesm)

# v0.2.4 (2021-04-14)

* adapt to X.509 0.12.0 (#23 @dinosaure) by completing the pattern match in
  oacmel (still, only RSA account keys are supported)

# v0.2.3 (2021-01-21)

* adapt to mirage-crypto-pk 0.8.9 changes (d = e ^ -1 mod lam n) #22

# v0.2.2 (2020-04-09)

* adapt to x509 0.11.0 API #21

# v0.2.1 (2020-03-12)

* use mirage-crypto instead of nocrypto #20
* reorder arguments for nsupdate to avoid a labelled one at the end #20

# v0.2.0 (2020-02-18)

* support ACME as specified in RFC 8555 (letsencrypt v2 endpoints) #19
* support for the ALPN challenge as well #19

# v0.1.1 (2020-01-27)

* use X509.Signing_request.hostnames, introduced in x509 v0.9.0
* provide a custom log source

# v0.1.0 (2019-11-02)

* Initial release
