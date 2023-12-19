(** [dns_solver (fun domain content)] is a solver for dns-01 challenges.
    The provided function should return [Ok ()] once the authoritative
    name servers serve a TXT record at [domain] with the content. The
    [domain] already has the [_acme-challenge.] prepended. *)
val dns_solver :
  ([`raw] Domain_name.t -> string ->
   (unit, [ `Msg of string ]) result) -> Letsencrypt.Client.solver

(** [print_dns] outputs the DNS challenge solution, and waits for user input
    before continuing with ACME. *)
val print_dns : Letsencrypt.Client.solver

(** [nsupdate ~proto id now send ~recv ~keyname key ~zone]
    constructs a dns solver that sends a DNS update packet (using [send])
    and optionally waits for a signed reply (using [recv] if present) to solve
    challenges. The update is signed with a hmac transaction signature
    (DNS TSIG) using [now ()] as timestamp, and the [keyname] and [key] for
    the cryptographic material. The [zone] is the one to be used in the
    query section of the update packet. If signing, sending, or receiving
    fails, the error is reported. *)
val nsupdate : ?proto:Dns.proto -> int -> (unit -> Ptime.t) ->
  (Cstruct.t -> (unit, [ `Msg of string ]) result) ->
  ?recv:(unit -> (Cstruct.t, [ `Msg of string ]) result) ->
  zone:[ `host ] Domain_name.t ->
  keyname:'a Domain_name.t -> Dns.Dnskey.t -> Letsencrypt.Client.solver
