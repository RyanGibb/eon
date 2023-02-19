let letsencrypt_production_url =
  Uri.of_string "https://acme-v02.api.letsencrypt.org/directory"

let letsencrypt_staging_url =
  Uri.of_string "https://acme-staging-v02.api.letsencrypt.org/directory"

let sha256_and_base64 a = Primitives.sha256 a |> B64u.urlencode

let ( let* ) = Result.bind

module J = Yojson.Basic

type json = J.t

(* Serialize a json object without having spaces around. Dammit Yojson. *)
(* XXX. I didn't pay enough attention on escaping.
 * It is possible that this is okay; however, our encodings are nice. *)
(* NOTE: hannes thinks that Json.to_string (`String {|foo"bar|}) looks suspicious *)
let rec json_to_string ?(comma = ",") ?(colon = ":") : J.t -> string = function
  | `Null -> ""
  | `String s -> Printf.sprintf {|"%s"|} (String.escaped s)
  | `Bool b -> if b then "true" else "false"
  | `Float f -> string_of_float f
  | `Int i -> string_of_int i
  | `List l ->
    let s = List.map (json_to_string ~comma ~colon) l in
    "[" ^ (String.concat comma s) ^ "]"
  | `Assoc a ->
    let serialize_pair (key, value) =
      Printf.sprintf {|"%s"%s%s|} key colon (json_to_string ~comma ~colon value)
    in
    let s = List.map serialize_pair a in
    Printf.sprintf {|{%s}|} (String.concat comma s)

let of_string s =
  try Ok (J.from_string s) with
    Yojson.Json_error str -> Error (`Msg str)

let err_msg typ name json =
  Error (`Msg (Fmt.str "couldn't find %s %s in %s" typ name (J.to_string json)))

(* decoders *)
let string_val key json =
  match J.Util.member key json with
  | `String s -> Ok s
  | _ -> err_msg "string" key json

let opt_string_val key json =
  match J.Util.member key json with
  | `String s -> Ok (Some s)
  | `Null -> Ok None
  | _ -> err_msg "opt_string" key json

let json_val member json =
  match J.Util.member member json with
  | `Assoc j -> Ok (`Assoc j)
  | _ -> err_msg "json object" member json

let b64_z_val member json =
  let* s = string_val member json in
  B64u.urldecodez s

let b64_string_val member json =
  let* s = string_val member json in
  B64u.urldecode s

let assoc_val key json =
  match J.Util.member key json with
  | `Assoc _ | `Null as x -> Ok x
  | _ -> err_msg "assoc" key json

let list_val key json =
  match J.Util.member key json with
  | `List l -> Ok l
  | _ -> err_msg "list" key json

let opt_string_list key json =
  match J.Util.member key json with
  | `List l ->
    let xs =
      List.fold_left
        (fun acc -> function `String s -> s :: acc | _ -> acc)
        [] l
    in
    Ok (Some xs)
  | `Null -> Ok None
  | _ -> err_msg "string list" key json

let opt_bool key json =
  match J.Util.member key json with
  | `Bool b -> Ok (Some b)
  | `Null -> Ok None
  | _ -> err_msg "opt bool" key json

let decode_ptime str =
  match Ptime.of_rfc3339 str with
  | Ok (ts, _, _) -> Ok ts
  | Error `RFC3339 (_, err) ->
    Error (`Msg (Fmt.str "couldn't parse %s as rfc3339 %a"
                   str Ptime.pp_rfc3339_error err))

let maybe f = function
  | None -> Ok None
  | Some s ->
    let* s' = f s in
    Ok (Some s')

module Jwk = struct
  type key = X509.Public_key.t

  let encode = function
    | `RSA key ->
      let e, n = Primitives.pub_to_z key in
      `Assoc [
        "e", `String (B64u.urlencodez e);
        "kty", `String "RSA";
        "n", `String (B64u.urlencodez n);
      ]
    | `P256 key ->
      let cs = Mirage_crypto_ec.P256.Dsa.pub_to_cstruct key in
      let x, y = Cstruct.split cs ~start:1 32 in
      `Assoc [
        "crv", `String "P-256";
        "kty", `String "EC";
        "x", `String (B64u.urlencode (Cstruct.to_string x));
        "y", `String (B64u.urlencode (Cstruct.to_string y));
      ]
    | `P384 key ->
      let cs = Mirage_crypto_ec.P384.Dsa.pub_to_cstruct key in
      let x, y = Cstruct.split cs ~start:1 48 in
      `Assoc [
        "crv", `String "P-384";
        "kty", `String "EC";
        "x", `String (B64u.urlencode (Cstruct.to_string x));
        "y", `String (B64u.urlencode (Cstruct.to_string y));
      ]
    | `P521 key ->
      let cs = Mirage_crypto_ec.P521.Dsa.pub_to_cstruct key in
      let x, y = Cstruct.split cs ~start:1 66 in
      `Assoc [
        "crv", `String "P-521";
        "kty", `String "EC";
        "x", `String (B64u.urlencode (Cstruct.to_string x));
        "y", `String (B64u.urlencode (Cstruct.to_string y));
      ]
    | _ -> assert false

  let decode_json json =
    let* kty = string_val "kty" json in
    match kty with
    | "RSA" ->
      let* e = b64_z_val "e" json in
      let* n = b64_z_val "n" json in
      let* pub = Primitives.pub_of_z ~e ~n in
      Ok (`RSA pub)
    | "EC" ->
      let four = Cstruct.create 1 in
      Cstruct.set_uint8 four 0 0x04;
      let* x = Result.map Cstruct.of_string (b64_string_val "x" json) in
      let* y = Result.map Cstruct.of_string (b64_string_val "y" json) in
      let* crv = string_val "crv" json in
      begin match crv with
        | "P-256" ->
          let* pub =
            Result.map_error
              (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
              (Mirage_crypto_ec.P256.Dsa.pub_of_cstruct
                 (Cstruct.concat [ four ; x ; y ]))
          in
          Ok (`P256 pub)
        | "P-384" ->
          let* pub =
            Result.map_error
              (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
              (Mirage_crypto_ec.P384.Dsa.pub_of_cstruct
                 (Cstruct.concat [ four ; x ; y ]))
          in
          Ok (`P384 pub)
        | "P-521" ->
          let* pub =
            Result.map_error
              (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
              (Mirage_crypto_ec.P521.Dsa.pub_of_cstruct
                 (Cstruct.concat [ four ; x ; y ]))
          in
          Ok (`P521 pub)
        | x -> Error (`Msg (Fmt.str "unknown EC curve %s" x))
      end
    | x -> Error (`Msg (Fmt.str "unknown key type %s" x))

  let decode data =
    let* json = of_string data in
    decode_json json

  let thumbprint pub_key =
    let jwk = json_to_string (encode pub_key) in
    let h = Primitives.sha256 jwk in
    B64u.urlencode h
end

module Jws = struct
  type header = {
    alg : string;
    nonce : string option;
    jwk : Jwk.key option;
  }

  let encode ?(protected = []) ~data ?nonce priv =
    let alg, hash = match priv with
      | `RSA _ -> "RS256", `SHA256
      | `P256 _ -> "ES256", `SHA256
      | `P384 _ -> "ES384", `SHA384
      | `P521 _ -> "ES512", `SHA512
      | _ -> assert false
    in
    let protected =
      let n = match nonce with None -> [] | Some x -> [ "nonce", `String x ] in
      `Assoc (("alg", `String alg) :: protected @ n) |> json_to_string
    in
    let protected = protected |> B64u.urlencode in
    let payload = B64u.urlencode data in
    let signature =
      let m = protected ^ "." ^ payload in
      Primitives.sign hash priv m |> B64u.urlencode
    in
    let json =
      `Assoc [
        "protected", `String protected ;
        "payload", `String payload ;
        "signature", `String signature
      ]
    in
    json_to_string ~comma:", " ~colon:": " json

  let encode_acme ?kid_url ~data ?nonce url priv =
    let kid_or_jwk =
      match kid_url with
      | None -> "jwk", Jwk.encode (X509.Private_key.public priv)
      | Some url -> "kid", `String (Uri.to_string url)
    in
    let url = "url", `String (Uri.to_string url) in
    let protected = [ kid_or_jwk ; url ] in
    encode ~protected ~data ?nonce priv

  let decode_header protected_header =
    let* protected = of_string protected_header in
    let* jwk =
      match json_val "jwk" protected with
      | Ok key ->
        let* k = Jwk.decode_json key in
        Ok (Some k)
      | Error _ -> Ok None
    in
    let* alg = string_val "alg" protected in
    let nonce = Result.to_option (string_val "nonce" protected) in
    Ok { alg ; nonce ; jwk }

  let decode ?pub data =
    let* jws = of_string data in
    let* protected64 = string_val "protected" jws in
    let* payload64 = string_val "payload" jws in
    let* signature = b64_string_val "signature" jws in
    let* protected = B64u.urldecode protected64 in
    let* header = decode_header protected in
    let* payload = B64u.urldecode payload64 in
    let* pub =
      match pub, header.jwk with
      | Some pub, _ -> Ok pub
      | None, Some pub -> Ok pub
      | None, None -> Error (`Msg "no public key found")
    in
    let verify m s =
      match header.alg with
      | "RS256" -> Primitives.verify `SHA256 pub m s
      | "ES256" -> Primitives.verify `SHA256 pub m s
      | "ES384" -> Primitives.verify `SHA384 pub m s
      | "ES512" -> Primitives.verify `SHA512 pub m s
      | _ -> false
    in
    let m = protected64 ^ "." ^ payload64 in
    if verify m signature then
      Ok (header, payload)
    else
      Error (`Msg "signature verification failed")
end

let uri s = Ok (Uri.of_string s)

module Directory = struct
  type meta = {
    terms_of_service : Uri.t option;
    website : Uri.t option;
    caa_identities : string list option;
    (* external_account_required *)
  }

  let pp_meta ppf { terms_of_service ; website ; caa_identities } =
    Fmt.pf ppf "terms of service: %a@,website %a@,caa identities %a"
      Fmt.(option ~none:(any "no tos") Uri.pp_hum) terms_of_service
      Fmt.(option ~none:(any "no website") Uri.pp_hum) website
      Fmt.(option ~none:(any "no CAA") (list ~sep:(any ", ") string))
      caa_identities

  let meta_of_json = function
    | `Assoc _ as json ->
      let* terms_of_service =
        let* tos = opt_string_val "termsOfService" json in
        maybe uri tos
      in
      let* website =
        let* w = opt_string_val "website" json in
        maybe uri w
      in
      let* caa_identities = opt_string_list "caaIdentities" json in
      Ok (Some { terms_of_service ; website ; caa_identities })
    | _ -> Ok None

  type t = {
    new_nonce : Uri.t;
    new_account : Uri.t;
    new_order : Uri.t;
    new_authz : Uri.t option;
    revoke_cert : Uri.t;
    key_change : Uri.t;
    meta : meta option;
  }

  let pp ppf dir =
    Fmt.pf ppf "new nonce %a@,new account %a@,new order %a@,new authz %a@,revoke cert %a@,key change %a@,meta %a"
      Uri.pp_hum dir.new_nonce Uri.pp_hum dir.new_account Uri.pp_hum dir.new_order
      Fmt.(option ~none:(any "no authz") Uri.pp_hum) dir.new_authz
      Uri.pp_hum dir.revoke_cert Uri.pp_hum dir.key_change
      Fmt.(option ~none:(any "no meta") pp_meta) dir.meta

  let decode s =
    let* json = of_string s in
    let* new_nonce =
      let* nn = string_val "newNonce" json in
      uri nn
    in
    let* new_account =
      let* na = string_val "newAccount" json in
      uri na
    in
    let* new_order =
      let* no = string_val "newOrder" json in
      uri no
    in
    let* new_authz =
      let* na = opt_string_val "newAuthz" json in
      maybe uri na
    in
    let* revoke_cert =
      let* rc = string_val "revokeCert" json in
      uri rc
    in
    let* key_change =
      let* kc = string_val "keyChange" json in
      uri kc
    in
    let* meta =
      let* m = assoc_val "meta" json in
      meta_of_json m
    in
    Ok { new_nonce ; new_account ; new_order ; new_authz ; revoke_cert ;
         key_change ; meta }
end

module Account = struct
  type t = {
    account_status : [ `Valid | `Deactivated | `Revoked ];
    contact : string list option;
    terms_of_service_agreed : bool option;
    (* externalAccountBinding *)
    orders : Uri.t option;
    initial_ip : string option;
    created_at : Ptime.t option;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Valid -> "valid"
        | `Deactivated -> "deactivated"
        | `Revoked -> "revoked")

  let pp ppf a =
    Fmt.pf ppf "status %a@,contact %a@,terms of service agreed %a@,orders %a@,initial IP %a@,created %a"
      pp_status a.account_status
      Fmt.(option ~none:(any "no contact") (list ~sep:(any ", ") string))
      a.contact
      Fmt.(option ~none:(any "unknown") bool) a.terms_of_service_agreed
      Fmt.(option ~none:(any "unknown") Uri.pp_hum) a.orders
      Fmt.(option ~none:(any "unknown") string) a.initial_ip
      Fmt.(option ~none:(any "unknown") (Ptime.pp_rfc3339 ())) a.created_at

  let status_of_string = function
    | "valid" -> Ok `Valid
    | "deactivated" -> Ok `Deactivated
    | "revoked" -> Ok `Revoked
    | s -> Error (`Msg (Fmt.str "unknown account status %s" s))

  (* "it's fine to not have a 'required' orders array" (in contrast to 8555)
     and seen in the wild when creating an account, or retrieving the account url
     of a key, or even fetching the account url. all with an account that never
     ever did an order... it seems to be a discrepancy from LE servers and
     RFC 8555 *)
  (* https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md
     or https://github.com/letsencrypt/boulder/issues/3335 contains more
     information *)
  let decode str =
    let* json = of_string str in
    let* account_status =
      let* s = string_val "status" json in
      status_of_string s
    in
    let* contact = opt_string_list "contact" json in
    let* terms_of_service_agreed = opt_bool "termsOfServiceAgreed" json in
    let* orders =
      let* o = opt_string_val "orders" json in
      maybe uri o
    in
    let* initial_ip = opt_string_val "initialIp" json in
    let* created_at =
      let* ca = opt_string_val "createdAt" json in
      maybe decode_ptime ca
    in
    Ok { account_status ; contact ; terms_of_service_agreed ; orders ;
         initial_ip ; created_at }
end

type id_type = [ `Dns ]

let pp_id_type ppf = function `Dns -> Fmt.string ppf "dns"

let pp_id = Fmt.(pair ~sep:(any " - ") pp_id_type string)

let id_type_of_string = function
  | "dns" -> Ok `Dns
  | s -> Error (`Msg (Fmt.str "only DNS typ is supported, got %s" s))

let decode_id json =
  let* typ =
    let* t = string_val "type" json in
    id_type_of_string t
  in
  let* id = string_val "value" json in
  Ok (typ, id)

let decode_ids ids =
  List.fold_left (fun acc json_id ->
      let* acc = acc in
      let* id = decode_id json_id in
      Ok (id :: acc))
    (Ok []) ids

module Order = struct
  type t = {
    order_status : [ `Pending | `Ready | `Processing | `Valid | `Invalid ];
    expires : Ptime.t option; (* required if order_status = pending | valid *)
    identifiers : (id_type * string) list;
    not_before : Ptime.t option;
    not_after : Ptime.t option;
    error : json option; (* "structured as problem document, RFC 7807" *)
    authorizations : Uri.t list;
    finalize : Uri.t;
    certificate : Uri.t option;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Pending -> "pending"
        | `Ready -> "ready"
        | `Processing -> "processing"
        | `Valid -> "valid"
        | `Invalid -> "invalid")

  let pp ppf o =
    Fmt.pf ppf "status %a@ expires %a@ identifiers %a@ not_before %a@ not_after %a@ error %a@ authorizations %a@ finalize %a@ certificate %a"
      pp_status o.order_status
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.expires
      Fmt.(list ~sep:(any ", ") pp_id) o.identifiers
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.not_before
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.not_after
      Fmt.(option ~none:(any "no error") J.pp) o.error
      Fmt.(list ~sep:(any ", ") Uri.pp_hum) o.authorizations
      Uri.pp_hum o.finalize
      Fmt.(option ~none:(any "no") Uri.pp_hum) o.certificate

  let status_of_string = function
    | "pending" -> Ok `Pending
    | "ready" -> Ok `Ready
    | "processing" -> Ok `Processing
    | "valid" -> Ok `Valid
    | "invalid" -> Ok `Invalid
    | s -> Error (`Msg (Fmt.str "unknown order status %s" s))

  let decode str =
    let* json = of_string str in
    let* order_status =
      let* s = string_val "status" json in
      status_of_string s
    in
    let* expires =
      let* e = opt_string_val "expires" json in
      maybe decode_ptime e
    in
    let* identifiers =
      let* i = list_val "identifiers" json in
      decode_ids i
    in
    let* not_before =
      let* nb = opt_string_val "notBefore" json in
      maybe decode_ptime nb
    in
    let* not_after =
      let* na = opt_string_val "notAfter" json in
      maybe decode_ptime na
    in
    let error =
      match J.Util.member "error" json with `Null -> None | x -> Some x
    in
    let* authorizations =
      let* auths = opt_string_list "authorizations" json in
      let* auths =
        Option.to_result
          ~none:(`Msg "no authorizations found in order")
          auths
      in
      Ok (List.map Uri.of_string auths)
    in
    let* finalize =
      let* f = string_val "finalize" json in
      uri f
    in
    let* certificate =
      let* c = opt_string_val "certificate" json in
      maybe uri c
    in
    Ok { order_status ; expires ; identifiers ; not_before ; not_after ; error ;
         authorizations ; finalize ; certificate }
end

module Challenge = struct
  type typ = [ `Dns | `Http | `Alpn ]

  let pp_typ ppf t =
    Fmt.string ppf (match t with `Dns -> "DNS" | `Http -> "HTTP" | `Alpn -> "ALPN")

  let typ_of_string = function
    | "tls-alpn-01" -> Ok `Alpn
    | "http-01" -> Ok `Http
    | "dns-01" -> Ok `Dns
    | s -> Error (`Msg (Fmt.str "unknown challenge typ %s" s))

  (* turns out, the only interesting ones are dns, http, alpn *)
  (* all share the same style *)
  type t = {
    challenge_typ : typ;
    url : Uri.t;
    challenge_status : [ `Pending | `Processing | `Valid | `Invalid ];
    token : string;
    validated : Ptime.t option;
    error : json option;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Pending -> "pending"
        | `Processing -> "processing"
        | `Valid -> "valid"
        | `Invalid -> "invalid")

  let pp ppf c =
    Fmt.pf ppf "status %a@,typ %a@,token %s@,url %a@,validated %a@,error %a"
      pp_status c.challenge_status
      pp_typ c.challenge_typ
      c.token
      Uri.pp_hum c.url
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) c.validated
      Fmt.(option ~none:(any "no error") J.pp) c.error

  let status_of_string = function
    | "pending" -> Ok `Pending
    | "processing" -> Ok `Processing
    | "valid" -> Ok `Valid
    | "invalid" -> Ok `Invalid
    | s -> Error (`Msg (Fmt.str "unknown order status %s" s))

  let decode json =
    let* challenge_typ =
      let* t = string_val "type" json in
      typ_of_string t
    in
    let* challenge_status =
      let* s = string_val "status" json in
      status_of_string s
    in
    let* url =
      let* u = string_val "url" json in
      uri u
    in
    (* in all three challenges, it's b64 url encoded (but the raw value never used) *)
    (* they MUST >= 128bit entropy, and not have any trailing = *)
    let* token = string_val "token" json in
    let* validated =
      let* v = opt_string_val "validated" json in
      maybe decode_ptime v
    in
    let error =
      match J.Util.member "error" json with `Null -> None | x -> Some x
    in
    Ok { challenge_typ ; challenge_status ; url ; token ; validated ; error }
end

module Authorization = struct
  type t = {
    identifier : id_type * string;
    authorization_status : [ `Pending | `Valid | `Invalid | `Deactivated | `Expired | `Revoked ];
    expires : Ptime.t option;
    challenges : Challenge.t list;
    wildcard : bool;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Pending -> "pending"
        | `Valid -> "valid"
        | `Invalid -> "invalid"
        | `Deactivated -> "deactivated"
        | `Expired -> "expired"
        | `Revoked -> "revoked")

  let pp ppf a =
    Fmt.pf ppf "status %a@,identifier %a@,expires %a@,challenges %a@,wildcard %a"
      pp_status a.authorization_status pp_id a.identifier
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) a.expires
      Fmt.(list ~sep:(any ",") Challenge.pp) a.challenges
      Fmt.bool a.wildcard

  let status_of_string = function
    | "pending" -> Ok `Pending
    | "valid" -> Ok `Valid
    | "invalid" -> Ok `Invalid
    | "deactivated" -> Ok `Deactivated
    | "expired" -> Ok `Expired
    | "revoked" -> Ok `Revoked
    | s -> Error (`Msg (Fmt.str "unknown order status %s" s))

  let decode str =
    let* json = of_string str in
    let* identifier =
      let* i = assoc_val "identifier" json in
      decode_id i
    in
    let* authorization_status =
      let* s = string_val "status" json in
      status_of_string s
    in
    let* expires =
      let* e = opt_string_val "expires" json in
      maybe decode_ptime e
    in
    let* challenges = list_val "challenges" json in
    let challenges =
      (* be modest in what you receive - there may be other challenges in the future *)
      List.fold_left (fun acc json ->
          match Challenge.decode json with
          | Error `Msg err ->
            Logs.warn (fun m -> m "ignoring challenge %a: parse error %s" J.pp json err);
            acc
          | Ok c -> c :: acc) [] challenges
    in
    (* TODO "MUST be present and true for orders containing a DNS identifier with wildcard. for others, it MUST be absent" *)
    let* wildcard =
      Result.map
        (Option.value ~default:false)
        (opt_bool "wildcard" json)
    in
    Ok { identifier ; authorization_status ; expires ; challenges ; wildcard }
end

module Error = struct
  (* from http://www.iana.org/assignments/acme urn registry *)
  type t = {
    err_typ : [
      | `Account_does_not_exist | `Already_revoked | `Bad_csr | `Bad_nonce
      | `Bad_public_key | `Bad_revocation_reason | `Bad_signature_algorithm
      | `CAA | `Connection | `DNS | `External_account_required
      | `Incorrect_response | `Invalid_contact | `Malformed | `Order_not_ready
      | `Rate_limited | `Rejected_identifier | `Server_internal | `TLS
      | `Unauthorized | `Unsupported_contact | `Unsupported_identifier
      | `User_action_required
    ];
    detail : string
  }

  let err_typ_to_string = function
    | `Account_does_not_exist -> "The request specified an account that does not exist"
    | `Already_revoked -> "The request specified a certificate to be revoked that has already been revoked"
    | `Bad_csr -> "The CSR is unacceptable (e.g., due to a short key)"
    | `Bad_nonce -> "The client sent an unacceptable anti-replay nonce"
    | `Bad_public_key -> "The JWS was signed by a public key the server does not support"
    | `Bad_revocation_reason -> "The revocation reason provided is not allowed by the server"
    | `Bad_signature_algorithm -> "The JWS was signed with an algorithm the server does not support"
    | `CAA -> "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate"
    (*  | `Compound -> "Specific error conditions are indicated in the 'subproblems' array" *)
    | `Connection -> "The server could not connect to validation target"
    | `DNS -> "There was a problem with a DNS query during identifier validation"
    | `External_account_required -> "The request must include a value for the 'externalAccountBinding' field"
    | `Incorrect_response -> "Response received didn't match the challenge's requirements"
    | `Invalid_contact -> "A contact URL for an account was invalid"
    | `Malformed -> "The request message was malformed"
    | `Order_not_ready -> "The request attempted to finalize an order that is not ready to be finalized"
    | `Rate_limited -> "The request exceeds a rate limit"
    | `Rejected_identifier -> "The server will not issue certificates for the identifier"
    | `Server_internal -> "The server experienced an internal error"
    | `TLS -> "The server received a TLS error during validation"
    | `Unauthorized -> "The client lacks sufficient authorization"
    | `Unsupported_contact -> "A contact URL for an account used an unsupported protocol scheme"
    | `Unsupported_identifier -> "An identifier is of an unsupported type"
    | `User_action_required -> "Visit the 'instance' URL and take actions specified there"

  let pp ppf e =
    Fmt.pf ppf "%s, detail: %s" (err_typ_to_string e.err_typ) e.detail

  let err_typ_of_string str =
    let prefix = "urn:ietf:params:acme:error:" in
    let plen = String.length prefix in
    let err =
      if String.length str > plen && String.(equal prefix (sub str 0 plen)) then
        Some (String.sub str plen (String.length str - plen))
      else
        None
    in
    match err with
    | Some err ->
      (* from https://www.iana.org/assignments/acme/acme.xhtml (20200209) *)
      begin match err with
        | "accountDoesNotExist" -> Ok `Account_does_not_exist
        | "alreadyRevoked" -> Ok `Already_revoked
        | "badCSR" -> Ok `Bad_csr
        | "badNonce" -> Ok `Bad_nonce
        | "badPublicKey" -> Ok `Bad_public_key
        | "badRevocationReason" -> Ok `Bad_revocation_reason
        | "badSignatureAlgorithm" -> Ok `Bad_signature_algorithm
        | "caa" -> Ok `CAA
        (* | "compound" -> Ok `Compound see 'subproblems' array *)
        | "connection" -> Ok `Connection
        | "dns" -> Ok `DNS
        | "externalAccountRequired" -> Ok `External_account_required
        | "incorrectResponse" -> Ok `Incorrect_response
        | "invalidContact" -> Ok `Invalid_contact
        | "malformed" -> Ok `Malformed
        | "orderNotReady" -> Ok `Order_not_ready
        | "rateLimited" -> Ok `Rate_limited
        | "rejectedIdentifier" -> Ok `Rejected_identifier
        | "serverInternal" -> Ok `Server_internal
        | "tls" -> Ok `TLS
        | "unauthorized" -> Ok `Unauthorized
        | "unsupportedContact" -> Ok `Unsupported_contact
        | "unsupportedIdentifier" -> Ok `Unsupported_identifier
        | "userActionRequired" -> Ok `User_action_required
        | s -> Error (`Msg (Fmt.str "unknown acme error typ %s" s))
      end
    | None -> Error (`Msg (Fmt.str "unknown error type %s" str))

  let decode str =
    let* json = of_string str in
    let* err_typ =
      let* t = string_val "type" json in
      err_typ_of_string t
    in
    let* detail = string_val "detail" json in
    Ok { err_typ ; detail }
end
