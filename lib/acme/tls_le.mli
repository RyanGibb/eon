exception Le_error of string

val errcheck : ('a, [< `Msg of string ]) result -> 'a
val gen_account_key : unit -> X509.Private_key.t
val gen_private_key : unit -> X509.Private_key.t

val gen_cert :
  ?account_key:X509.Private_key.t ->
  ?private_key:X509.Private_key.t ->
  email:string ->
  org:string ->
  domain:[ `raw ] Domain_name.t ->
  endpoint:Uri.t ->
  solver:Letsencrypt.Client.solver ->
  < clock : _ Eio.Time.clock ; net : _ Eio.Net.t ; .. > ->
  X509.Certificate.t list * X509.Private_key.t * X509.Private_key.t * X509.Signing_request.t

val tls_config :
  ?alpn_protocols:string list ->
  cert:X509.Certificate.t list ->
  private_key:X509.Private_key.t ->
  unit ->
  Tls.Config.server
