(** {1:Let's encrypt challenge with [paf].}

    [Paf] provides a layer to be able to:
    1) launch a simple HTTP server which will do the Let's encrypt challenge
    2) launch a simple HTTP client to ask a new certificate

    The HTTP server must be behind the domain-name for which you want a
    certificate.

    The usual way to get a certificate is to prepare a {!type:configuration}
    value, prepare the HTTP server and launch concurrently the server and the
    client with an ability to stop the server when the client finish the job:

    {[
      module LE = LE.Make (Time) (Stack)

      let provision ctx =
        Paf.init ~port:80 (Stack.tcp stackv4v6) >>= fun t ->
        let service = Paf.http_service
          ~error_handler:ignore_error
          (fun _ -> LE.request_handler) in
        let stop = Lwt_switch.create () in
        let `Initialized th0 = Paf.serve ~stop service in
        let th1 =
          LE.provision_certificate
            ~production:false
            configuration
            ctx 
          >>= fun certificates ->
          Lwt_switch.turn_off stop >>= fun () ->
          Lwt.return certificates in
        Lwt.both th0 th1 >>= function
        | ((), Ok certificates) -> ...
        | ((), Error _) -> ...
    ]}

    The client requires an {!type:Http_mirage_client.t} to be able to do HTTP
    requests ([http/1.1] or [h2]) which can be made by
    {!val:Http_mirage_client.Make.connect}. *)

type configuration = {
  email : Emile.mailbox option;
  certificate_seed : string option;
  certificate_key_type : X509.Key_type.t;
  certificate_key_bits : int option;
  hostname : [ `host ] Domain_name.t;
  account_seed : string option;
  account_key_type : X509.Key_type.t;
  account_key_bits : int option;
}

module Make (Time : Mirage_time.S) (Stack : Tcpip.Stack.V4V6) : sig
  type nonrec configuration = configuration = {
    email : Emile.mailbox option;
    certificate_seed : string option;
    certificate_key_type : X509.Key_type.t;
    certificate_key_bits : int option;
    hostname : [ `host ] Domain_name.t;
    account_seed : string option;
    account_key_type : X509.Key_type.t;
    account_key_bits : int option;
  }

  val request_handler :
    Ipaddr.t * int -> Httpaf.Server_connection.request_handler

  val provision_certificate :
    ?tries:int ->
    ?production:bool ->
    configuration ->
    Http_mirage_client.t ->
    (Tls.Config.own_cert, [> `Msg of string ]) result Lwt.t

  val initialise :
    ctx:Http_mirage_client.t ->
    endpoint:Uri.t ->
    ?email:string ->
    X509.Private_key.t ->
    (Letsencrypt.Client.t, [> `Msg of string ]) result Lwt.t
  (** [initialise ~ctx ~endpoint ~email priv] constructs a
      {!type:Letsencrypt.Client.t} by looking up the directory and account of
      [priv] at [endpoint]. If no account is registered yet, a new account is
      created with contact information of [email]. The terms of service are
      agreed on. *)

  val sign_certificate :
    ctx:Http_mirage_client.t ->
    Letsencrypt.Client.solver ->
    Letsencrypt.Client.t ->
    (int -> unit Lwt.t) ->
    X509.Signing_request.t ->
    (X509.Certificate.t list, [> `Msg of string ]) result Lwt.t
  (** [sign_certificate ~ctx solver t sleep csr] orders a certificate for the
      names in the signing request [csr], and solves the requested challenges. *)
end
