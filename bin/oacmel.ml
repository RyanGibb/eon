
(*
let dns_out ip cs =
  let out = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let server = Lwt_unix.ADDR_INET (ip, 53) in
  let bl = Cstruct.length cs in
  Lwt_unix.sendto out (Cstruct.to_bytes cs) 0 bl [] server >>= fun n ->
  (* TODO should listen for a reply from NS, report potential errors and retransmit if UDP frame got lost *)
  if n = bl then Lwt.return_ok () else Lwt.return_error (`Msg "couldn't send nsupdate")
*)

let doit env email endpoint account_key solver sleep csr =
  Logs.app (fun m -> m "doit %s" endpoint);
  Letsencrypt.Client.initialise env ~endpoint:(Uri.of_string endpoint) ?email account_key |> function
  | Ok t -> Letsencrypt.Client.sign_certificate env solver t sleep csr
  | Error e -> Error e

let main _ priv_pem csr_pem email solver acme_dir ip key endpoint cert zone =
  Eio_main.run @@ fun env ->
  Eio.Ctf.with_tracing @@ fun () ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let r =
    let ( let* ) = Result.bind in
    let priv_pem = Eio.Path.load (Eio.Path.(Eio.Stdenv.fs env / priv_pem)) in
    let csr_pem = Eio.Path.load (Eio.Path.(Eio.Stdenv.fs env / csr_pem)) in
    let f_exists = Sys.file_exists cert in
    if f_exists then
      Error (`Msg (Fmt.str "output file %s already exists" cert))
    else
      let* account_key = X509.Private_key.decode_pem (Cstruct.of_string priv_pem) in
      let* request = X509.Signing_request.decode_pem (Cstruct.of_string csr_pem) in
      let solver =
        match solver, acme_dir, ip, key with
        | _, Some path, None, None -> (* using http solver! *)
          Logs.app (fun m -> m "using http solver, writing to %s" path);
          let solve_challenge _ ~prefix:_ ~token ~content =
            (* now, resource has .well-known/acme-challenge prepended *)
            let path = Eio.Path.(Eio.Stdenv.fs env / path / token) in
            Eio.Path.save ~create:(`Exclusive 0o600) path content;
            Ok ()
          in
          Letsencrypt.Client.http_solver solve_challenge
          (*
        | _, None, Some ip, Some (keyname, key) ->
          Logs.app (fun m -> m "using dns solver, writing to %a" Ipaddr.V4.pp ip);
          let ip' = Ipaddr_unix.V4.to_inet_addr ip in
          let zone = match zone with
            | None -> Domain_name.(host_exn (drop_label_exn ~amount:2 keyname))
            | Some x -> Domain_name.(host_exn (of_string_exn x))
          in
          let random_id = Randomconv.int16 Mirage_crypto_rng.generate in
          Letsencrypt_dns.nsupdate random_id Ptime_clock.now (dns_out ip') ~keyname key ~zone
        | Some `Dns, None, None, None ->
          Logs.app (fun m -> m "using dns solver");
          Letsencrypt_dns.print_dns
          *)
        | Some `Http, None, None, None ->
          Logs.app (fun m -> m "using http solver");
          Letsencrypt.Client.print_http
        | Some `Alpn, None, None, None ->
          Logs.app (fun m -> m "using alpn solver");
          Letsencrypt.Client.print_alpn
        | _ ->
          invalid_arg "unsupported combination of acme_dir, ip, and key"
      in
      let sleep n = Eio.Time.sleep env#clock (float_of_int n) in
      match doit env email endpoint account_key solver sleep request with
      | Error e -> Error e
      | Ok t ->
        Logs.info (fun m -> m "Certificates downloaded");
        let path = Eio.Path.(Eio.Stdenv.fs env / cert) in
        Eio.Path.save ~create:(`Exclusive 0o600) path (Cstruct.to_string @@ X509.Certificate.encode_pem_multiple t);
        Ok ()
  in
  match r with
  | Ok _ -> `Ok ()
  | Error (`Msg e) ->
    Logs.err (fun m -> m "Error %s" e) ;
    `Error ()

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ())

open Cmdliner

let priv_pem =
  let doc = "File containing the PEM-encoded private key." in
  Arg.(value & opt string "account.pem" & info ["account-key"] ~docv:"FILE" ~doc)

let csr_pem =
  let doc = "File containing the PEM-encoded CSR." in
  Arg.(value & opt string "csr.pem" & info ["csr"] ~docv:"FILE" ~doc)

let acme_dir =
  let doc =
    "Base path for where to write challenges. " ^
    "For letsencrypt, it must be the one serving " ^
    "http://example.com/.well-known/acme-challenge/" in
  Arg.(value & opt (some string) None & info ["acme_dir"] ~docv:"DIR" ~doc)

let ip =
  let doc = "ip address of authoritative DNS server" in
  let ip = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  Arg.(value & opt (some ip) None & info ["ip"] ~doc)

let key =
  let doc = "nsupdate key (name:hash:b64-encoded-value)" in
  let pp_name_dnskey ppf (name, key) =
    Fmt.pf ppf "%a %a" Domain_name.pp name Dns.Dnskey.pp key
  in
  let dnskey = Arg.conv (Dns.Dnskey.name_key_of_string, pp_name_dnskey) in
  Arg.(value & opt (some dnskey) None & info ["key"] ~doc)

let endpoint =
  let doc = "ACME endpoint" in
  Arg.(value & opt string (Uri.to_string Letsencrypt.letsencrypt_staging_url) & info ["endpoint"] ~doc)

let zone =
  let doc = "Zone for nsupdate packet (defaults to key with first two labels dropped)" in
  Arg.(value & opt (some string) None & info ["zone"] ~doc)

let cert =
  let doc = "filename where to store the certificate" in
  Arg.(value & opt string "certificate.pem" & info ["cert"] ~doc)

let email =
  let doc = "Contact eMail for registering new keys" in
  Arg.(value & opt (some string) None & info ["email"] ~doc)

let solver =
  let doc = "Which solver to use (printing instructions and awaits user setup). Possible values are dns, http, or alpn. Only required if acme-dir or dns credentials are not provided." in
  let solvers =
    [ ("dns", `Dns) ; ("http", `Http) ; ("alpn", `Alpn) ]
  in
  Arg.(value & opt (some (enum solvers)) None & info ["solver"] ~doc)

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let info =
  let doc = "just another ACME client" in
  let man = [
      `S "DESCRIPTION"; `P "This is software is experimental. Don't use it.";
      `S "BUGS"; `P "Email bug reports to <maker@tumbolandia.net>";
    ] in
  Term.info "oacmel" ~version:"%%VERSION%%" ~doc ~man

let () =
  Printexc.record_backtrace true;
  let cli = Term.(const main $ setup_log $ priv_pem $ csr_pem $ email $ solver $ acme_dir $ ip $ key $ endpoint $ cert $ zone) in
  match Term.eval (cli, info) with
  | `Error _ -> exit 1
  | _        -> exit 0
