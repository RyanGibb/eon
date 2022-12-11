(** [Letsencrypt]: for when you love authorities.

    Letsencrypt is an implementation of the ACME protocol, for automating the
    generation of HTTPS certificates.

    Currently, this library has been tested (and is working) only with
    Letsencrypt servers.
 *)
val letsencrypt_production_url : Uri.t
val letsencrypt_staging_url : Uri.t

val sha256_and_base64 : string -> string

(** ACME Client.

    This module provides client commands.
    Note: right now this module implements only the strict necessary
    in order to register an account, solve http-01 challenges provided by the CA,
    and fetch the certificate.
    This means that you will be able to maintain your server with this.
 *)
module Client: sig
  type t

  type solver = {
    typ : [ `Dns | `Http | `Alpn ];
    solve_challenge : token:string -> key_authorization:string ->
      [`host] Domain_name.t -> (unit, [ `Msg of string]) result;
  }

  (** [http_solver (fun domain ~prefix ~token ~content)] is a solver for
      http-01 challenges. The provided function should return [Ok ()] once the
      web server at [domain] serves [content] as [prefix/token]:
      a GET request to http://[domain]/[prefix]/[token] should return [content].
      The [prefix] is ".well-known/acme-challenge".
  *)
  val http_solver :
    ([`host] Domain_name.t -> prefix:string -> token:string -> content:string ->
     (unit, [ `Msg of string ]) result) -> solver

  (** [print_http] outputs the HTTP challenge solution, and waits for user input
      before continuing with ACME. *)
  val print_http : solver

  (** [alpn_solver ~key_type ~bits (fun domain ~alpn private_key certificate)]
      is a solver for tls-alpn-01 challenges. The provided function should
      return [Ok ()] once the TLS server at [domain] serves the self-signed
      [certificate] (with [private_key]) under the ALPN [alpn] ("acme-tls/1").
      The [key_type] and [bits] are used for the self-signed certificate, while
      [bits] is only relevant if [key_type] is `RSA (default: RSA with 2048
      bits). *)
  val alpn_solver :
    ?key_type:X509.Key_type.t -> ?bits:int ->
    ([`host] Domain_name.t -> alpn:string -> X509.Private_key.t ->
     X509.Certificate.t -> (unit, [ `Msg of string ]) result) -> solver

  (** [print_alpn] outputs the ALPN challenge solution, and waits for user input
      before continuing with ACME. *)
  val print_alpn : solver

    (** [initialise ~ctx ~endpoint ~email priv] constructs a [t] by
        looking up the directory and account of [priv] at [endpoint]. If no
        account is registered yet, a new account is created with contact
        information of [email]. The terms of service are agreed on. *)
  val initialise : < net : #Eio.Net.t; .. > -> endpoint:Uri.t -> ?email:string ->
      X509.Private_key.t -> (t, [> `Msg of string ]) result

    (** [sign_certificate ~ctx solver t sleep csr] orders a certificate for
        the names in the signing request [csr], and solves the requested
        challenges. *)
    val sign_certificate : < net : #Eio.Net.t; .. > ->
      solver -> t -> (int -> unit) ->
      X509.Signing_request.t ->
      (X509.Certificate.t list, [> `Msg of string ]) result
      (* TODO: use X509.Certificate.t * list *)

end

(* a TODO list of stuff not implemented in respect to 8555:
   - incomplete orders (cancel the authorizations, get rid of orders)
     -> otherwise may hit rate limiting
   - deal with errors we can deal with
     -- connection failures / timeouts
     -- cohttp uses Lwt exceptions at times
   - make next_nonce immutable, and pass it through
   - errors with "subproblems" (deal with them? decode them?)
   - "SHOULD user interaction" to accept terms of service
   - external account binding (data in json objects)
   - 7.3.2 account update
   - 7.3.3 changes of terms of service
   - 7.3.4 external binding
   - 7.3.5 account key rollover
   - 7.3.6 account deactivation
   - 7.4.1 pre-auth newAuth
   - 7.5 identifier authorization (+ 8) - WIP
     -> dns challenge: cleanup RRs once invalid / valid
   - 7.6 certificate revocation
*)
