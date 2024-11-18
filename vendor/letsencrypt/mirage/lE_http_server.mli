(** A simple ALPN server which already resolve Let's encrypt certificates.

    This module is to help the user to launch an ALPN server (and be able to
    handle [http/1.1] and [h2] requests) through a TLS certificate provided by
    Let's encrypt. The challenge is done {i via} HTTP (unlike the ALPN challenge
    offered by Let's encrypt). The [.well-known/*] path is therefore used and
    the user {b should not} define such a route. *)

module Make
    (Time : Mirage_time.S)
    (Stack : Tcpip.Stack.V4V6)
    (Random : Mirage_crypto_rng_mirage.S)
    (Mclock : Mirage_clock.MCLOCK)
    (Pclock : Mirage_clock.PCLOCK) : sig
  val get_certificates :
    yes_my_port_80_is_reachable_and_unused:Stack.t ->
    production:bool ->
    LE.configuration ->
    Http_mirage_client.t ->
    (Tls.Config.own_cert, [> `Msg of string ]) result Lwt.t
  (** [get_certificates ~yes_my_port_80_is_reachable_and_unused ~production cfg client]
      tries to resolve the Let's encrypt challenge by initiating an HTTP server
      on port 80 and handling requests from it with [ocaml-letsencrypt].

      This resolution requires that your domain name (requested in the given
      [cfg.hostname]) redirects Let's encrypt to this HTTP server. You probably
      need to check your DNS configuration.

      The [client] value can be made by {!val:Http_mirage_client.Make.connect}
      to be able to launch HTTP requests to Let's encrypt. *)

  module Paf : module type of Paf_mirage.Make (Stack.TCP)

  val with_lets_encrypt_certificates :
    ?port:int ->
    ?alpn_protocols:string list ->
    Stack.t ->
    production:bool ->
    LE.configuration ->
    Http_mirage_client.t ->
    (Paf.TLS.flow, Ipaddr.t * int) Alpn.server_handler ->
    (unit, [> `Msg of string ]) result Lwt.t
  (** [with_lets_encrypt_certificates ?port ?alpn_protocols stackv4v6 ~production cfg client handler]
      launches 2 servers:
      - An HTTP/1.1 server which handles let's encrypt challenges and
        redirections
      - An ALPN server (which handles HTTP/1.1 and H2 by default, otherwise you
        can specify protocols via the [alpn_protocol] argument) which run the
        user's request handler

      The [client] value can be made by {!val:Http_mirage_client.Make.connect}
      to be able to launch HTTP requests to Let's encrypt.
  
      Every 80 days, the fiber re-askes a new certificate from let's encrypt and
      re-update the ALPN server with this new certificate. The HTTP/1.1 server
      does the redirection to the hostname defined into the given [cfg].
  
      {b NOTE}: For the [alpn_protocols] argument, only ["h2"], ["http/1.1"] and
      ["http/1.0"] are handled. Any others protocols will be {b ignored}! The
      order of protocols matters. If ["h2"] is the first one and the client
      handles the ["h2"] protocol, server and client agree to use this protocol
      (even if both handle ["http/1.1"]).

      The default value of [alpn_protocols] prioritises ["http/1.1"] as the
      protocol which should be picked by the client. *)
end
