module Eiox = struct
  (* UPSTREAM: need an Eio file exists check without opening *)
  let file_exists f =
    Eio.Switch.run @@ fun sw ->
    try
      ignore (Eio.Path.open_in ~sw f);
      true
    with _ -> false
end

let generate_cert ~email ~domain ~org cert_root prod server_state env =
  let read_pem filepath decode_pem =
    match Eiox.file_exists filepath with
    | true -> Some (Eio.Path.load filepath |> Cstruct.of_string |> decode_pem |> Tls_le.errcheck)
    | false -> None
  in
  let write_pem filepath pem = Eio.Path.save ~create:(`Or_truncate 0o600) filepath (pem |> Cstruct.to_string) in
  let ( / ) = Eio.Path.( / ) in
  let open X509 in
  Eio.Switch.run @@ fun sw ->
  let cert_dir = Eio.Path.open_dir ~sw (env#fs / Domain_name.to_string domain / cert_root) in
  let account_key_file = cert_dir / "account.pem" in
  let private_key_file = cert_dir / "privkey.pem" in
  let csr_file = cert_dir / "csr.pem" in
  let cert_file = cert_dir / "fullcert.pem" in
  let account_key = read_pem account_key_file Private_key.decode_pem in
  let private_key = read_pem private_key_file Private_key.decode_pem in
  try
    let cert, account_key, private_key, csr =
      Dns_acme.provision_cert prod server_state env ?account_key ?private_key ~email [ domain ] ~org
    in
    write_pem account_key_file (Private_key.encode_pem account_key);
    write_pem private_key_file (Private_key.encode_pem private_key);
    write_pem csr_file (Signing_request.encode_pem csr);
    write_pem cert_file (Certificate.encode_pem_multiple cert);
    Eio.Path.native_exn cert_dir
  with Tls_le.Le_error msg -> "Error: " ^ msg

let read_request sock =
  let buffer = Eio.Buf_read.of_flow ~max_size:4096 sock in
  let email = Eio.Buf_read.line buffer in
  let org = Eio.Buf_read.line buffer in
  let domain = Eio.Buf_read.line buffer in
  Eio.Flow.shutdown sock `Receive;
  (email, (match org with "" -> None | o -> Some o), domain)

let run zonefiles log_level addressStrings port proto prod cert_root socket_path authorative =
  Eio_main.run @@ fun env ->
  let log = log_level Format.std_formatter in
  let addresses = Server_args.parse_addresses port addressStrings in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact env#secure_random buf;
    buf
  in
  let server_state =
    let trie, keys = Zonefile.parse_zonefiles ~fs:env#fs zonefiles in
    let trie =
      match authorative with
      | None -> trie
      | Some authorative -> Dns_trie.insert Domain_name.root Dns.Rr_map.Soa (Dns.Soa.create authorative) trie
    in
    ref @@ Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign trie
  in

  Eio.Switch.run @@ fun sw ->
  Eio.Fiber.fork ~sw (fun () ->
      Dns_server_eio.primary ~net:env#net ~clock:env#clock ~mono_clock:env#mono_clock ~proto server_state log addresses);

  let socket = Eio.Net.listen ~backlog:128 ~sw env#net (`Unix socket_path) in
  while true do
    let sock, _addr = Eio.Net.accept ~sw socket in
    Eio.Fiber.fork ~sw (fun () ->
        let email, org, domain = read_request sock in
        let msg =
          match Domain_name.of_string domain with
          | Error (`Msg e) -> "Error: " ^ e
          | Ok domain -> generate_cert ~email ~domain ~org cert_root prod server_state env
        in
        Eio.traceln "Recieved request: email '%s'; '%s'domain '%s'" email
          (match org with None -> "" | Some o -> Fmt.str "; org '%s' " o)
          domain;
        Eio.Flow.copy_string msg sock;
        Eio.Flow.shutdown sock `All)
  done

let () =
  let open Cmdliner in
  let open Server_args in
  let cmd =
    let prod =
      let doc = "Production certification generation." in
      Arg.(value & flag & info [ "prod" ] ~doc)
    in
    let cert_root =
      let doc = "Directory to store the certificates and keys in at path <cert-root>/<domain>/." in
      Arg.(value & opt string "certs" & info [ "cert-root" ] ~doc)
    in
    let socket_path =
      let doc = "The path to the Unix domain socket." in
      Arg.(value & opt string "/run/lend.socket" & info [ "s"; "socket" ] ~docv:"SOCKET_PATH" ~doc)
    in
    let authorative =
      let doc = "Domain(s) for which the nameserver is authorative for, if not passed in zonefiles." in
      Arg.(value & opt (some (conv (Domain_name.of_string, Domain_name.pp))) None & info [ "a"; "authorative" ] ~doc)
    in
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.level_1 $ addresses $ port $ proto $ prod $ cert_root $ socket_path
        $ authorative)
    in
    let doc = "Let's Encrypt Nameserver Daemon" in
    let info = Cmd.info "lend" ~doc ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
