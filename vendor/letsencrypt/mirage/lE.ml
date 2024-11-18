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

module HTTP : Letsencrypt.HTTP_client.S with type ctx = Http_mirage_client.t =
struct
  type ctx = Http_mirage_client.t

  module Headers = struct
    type t = (string * string) list

    let add lst k v = (String.lowercase_ascii k, v) :: lst
    let init_with k v = [ String.lowercase_ascii k, v ]
    let get lst k = List.assoc_opt (String.lowercase_ascii k) lst
    let get_location lst = Option.map Uri.of_string (get lst "location")
    let to_string = Fmt.to_to_string Fmt.(Dump.list (Dump.pair string string))
  end

  module Body = struct
    type t = string

    let to_string = Lwt.return
    let of_string x = x
  end

  module Response = struct
    type t = Http_mirage_client.response

    let status { Http_mirage_client.status; _ } = Http_mirage_client.Status.to_code status
    let headers { Http_mirage_client.headers; _ } = Http_mirage_client.Headers.to_list headers
  end

  let get_or_fail msg = function
    | Some ctx -> ctx
    | None -> failwith msg

  open Lwt.Infix

  let head ?ctx ?headers uri =
    let ctx = get_or_fail "http-mirage-client context is required" ctx in
    Http_mirage_client.request ctx ~meth:`HEAD ?headers (Uri.to_string uri)
      (fun _response () _str -> Lwt.return_unit)
      () >>= function
    | Ok (response, ()) -> Lwt.return response
    | Error err -> Fmt.failwith "%a" Mimic.pp_error err

  let get ?ctx ?headers uri =
    let ctx = get_or_fail "http-mirage-client context is required" ctx in
    Http_mirage_client.request ctx ~meth:`GET ?headers (Uri.to_string uri)
      (fun _response buf str -> Buffer.add_string buf str; Lwt.return buf)
      (Buffer.create 0x100) >>= function
    | Ok (response, buf) -> Lwt.return (response, Buffer.contents buf)
    | Error err -> Fmt.failwith "%a" Mimic.pp_error err

  let post ?ctx ?body ?chunked:_ ?headers uri =
    let ctx = get_or_fail "http-mirage-client context is required" ctx in
    Http_mirage_client.request ctx ~meth:`POST ?body ?headers (Uri.to_string uri)
      (fun _response buf str -> Buffer.add_string buf str; Lwt.return buf)
      (Buffer.create 0x100) >>= function
    | Ok (response, buf) -> Lwt.return (response, Buffer.contents buf)
    | Error err -> Fmt.failwith "%a" Mimic.pp_error err
end

module Log = (val let src = Logs.Src.create "letsencrypt.mirage" in
              Logs.src_log src : Logs.LOG)

module Make (Time : Mirage_time.S) (Stack : Tcpip.Stack.V4V6) = struct
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

  module Acme = Letsencrypt.Client.Make (HTTP)

  let gen_key ?seed ?bits key_type =
    X509.Private_key.generate ?seed ?bits key_type

  let csr key host =
    let host = Domain_name.to_string host in
    let cn =
      X509.
        [ Distinguished_name.(Relative_distinguished_name.singleton (CN host)) ]
    in
    X509.Signing_request.create cn key

  let prefix = (".well-known", "acme-challenge")
  let tokens = Hashtbl.create 1

  let solver _host ~prefix:_ ~token ~content =
    Hashtbl.replace tokens token content ;
    Lwt.return (Ok ())

  let request_handler (ipaddr, port) reqd =
    let req = Httpaf.Reqd.request reqd in
    Log.debug (fun m ->
        m "Let's encrypt request handler for %a:%d (%s)" Ipaddr.pp ipaddr port
          req.Httpaf.Request.target) ;
    match String.split_on_char '/' req.Httpaf.Request.target with
    | [ ""; p1; p2; token ]
      when String.equal p1 (fst prefix) && String.equal p2 (snd prefix) -> (
        match Hashtbl.find_opt tokens token with
        | Some data ->
            Log.debug (fun m -> m "Be able to respond to let's encrypt!") ;
            let headers =
              Httpaf.Headers.of_list
                [
                  ("content-type", "application/octet-stream");
                  ("content-length", string_of_int (String.length data));
                ] in
            let resp = Httpaf.Response.create ~headers `OK in
            Httpaf.Reqd.respond_with_string reqd resp data
        | None ->
            Log.warn (fun m -> m "Token %S not found!" token) ;
            let headers = Httpaf.Headers.of_list [ ("connection", "close") ] in
            let resp = Httpaf.Response.create ~headers `Not_found in
            Httpaf.Reqd.respond_with_string reqd resp "")
    | _ ->
        let headers = Httpaf.Headers.of_list [ ("connection", "close") ] in
        let resp = Httpaf.Response.create ~headers `Not_found in
        Httpaf.Reqd.respond_with_string reqd resp ""

  let provision_certificate ?(tries = 10) ?(production = false) cfg ctx =
    let ( >>? ) = Lwt_result.bind in
    let endpoint =
      if production
      then Letsencrypt.letsencrypt_production_url
      else Letsencrypt.letsencrypt_staging_url in
    let priv =
      gen_key ?seed:cfg.certificate_seed ?bits:cfg.certificate_key_bits
        cfg.certificate_key_type in
    match csr priv cfg.hostname with
    | Error _ as err -> Lwt.return err
    | Ok csr ->
        let open Lwt.Infix in
        let account_key =
          gen_key ?seed:cfg.account_seed ?bits:cfg.account_key_bits
            cfg.account_key_type in
        Acme.initialise ~ctx ~endpoint
          ?email:(Option.map Emile.to_string cfg.email)
          account_key
        >>? fun le ->
        Log.debug (fun m -> m "Let's encrypt state initialized.") ;
        let sleep sec = Time.sleep_ns (Duration.of_sec sec) in
        let solver = Letsencrypt.Client.http_solver solver in
        let rec go tries =
          Acme.sign_certificate ~ctx solver le sleep csr >>= function
          | Ok certs -> Lwt.return_ok (`Single (certs, priv))
          | Error (`Msg err) when tries > 0 ->
              Log.warn (fun m ->
                  m
                    "Got an error when we tried to get a certificate: %s \
                     (tries: %d)"
                    err tries) ;
              go (pred tries)
          | Error (`Msg err) ->
              Log.err (fun m ->
                  m "Got an error when we tried to get a certificate: %s" err) ;
              Lwt.return (Error (`Msg err)) in
        go tries

  let initialise ~ctx = Acme.initialise ~ctx
  let sign_certificate ~ctx = Acme.sign_certificate ~ctx
end
