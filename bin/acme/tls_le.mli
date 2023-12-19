exception Le_error of string

val gen_account_key : account_file:_ Eio.Path.t -> unit -> unit
(** [gen_account_key f] will write a new LE private account key into [f]. *)

val gen_csr :
  org:string ->
  email:string ->
  domain:string ->
  csr_file:_ Eio.Path.t ->
  key_file:_ Eio.Path.t -> unit -> unit
(** [gen_csr org email domain csr key] will write a new certificate
    signing request suitable for LE into [csr_file] and [key_file],
    with the values of [org], [email] and [domain] name. *)

val gen_cert :
  csr_pem:string ->
  account_pem:string ->
  email:string ->
  cert_file:_ Eio.Path.t ->
  endpoint:Uri.t ->
  solver:Letsencrypt.Client.solver ->
  < clock : (_ Eio.Time.clock); net : (_ Eio.Net.t); .. > -> unit
(** [gen_cert csr account email cert endpoint] will generate a certificate
    written into [cert] from the [csr] and [account] private key (made via {!gen_account_key{)
    and [email], using the ACME endpoint [endpoint]. *)

val tls_config :
  ?alpn_protocols:string list ->
  cert_root:_ Eio.Path.t ->
  org:string ->
  email:string ->
  domain:string ->
  endpoint:Uri.t ->
  solver:Letsencrypt.Client.solver ->
  < clock : (_ Eio.Time.clock); net : (_ Eio.Net.t); .. > -> Tls.Config.server
(** [tls_config] will generate a certificate file into [cert_root]
    with the [org], [email] and [domain] values specified, generated from the
    ACME [endpoint].  It returns a {!Tls.Config.server} suitable for
    using to serve TLS traffic. *)
