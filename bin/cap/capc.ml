type copts = { cap_uri : Uri.t }

let cert copts_env email domain org cert_root =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  let run_client cap =
    let domain_cap = Cap.Zone.init cap domain in
    (* callback for provisioned cert *)
    let cert_callback_cap =
      Cap.Cert_callback.local (fun result ->
          match result with
          | Error (`Capnp e) ->
              Format.eprintf "Capnp error: %a%!" Capnp_rpc.Error.pp e;
              Unix._exit 1
          | Error (`Remote msg) ->
              Printf.eprintf "Remote error: %s%!" msg;
              Unix._exit 1
          | Ok (cert, key) ->
              let write_pem filepath pem = Eio.Path.save ~create:(`Or_truncate 0o600) filepath pem in
              Eio.Switch.run @@ fun sw ->
              let ( / ) = Eio.Path.( / ) in
              let cert_dir = env#fs / cert_root / Domain_name.to_string domain in
              Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 cert_dir;
              let private_key_file = cert_dir / "privkey.pem" in
              let cert_file = cert_dir / "fullcert.pem" in
              write_pem private_key_file key;
              write_pem cert_file cert;
              Printf.printf "Updated cert for %s\n%!" (Domain_name.to_string domain))
    in
    match Cap.Domain.cert domain_cap ~email ~org ~subdomain:Domain_name.root cert_callback_cap with
    | Error (`Capnp e) -> Format.eprintf "%a" Capnp_rpc.Error.pp e
    | Ok () -> ()
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let update copts_env domain prereqs updates =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  let run_client cap =
    let domain_cap = Cap.Zone.init cap domain in
    match Cap.Domain.update domain_cap prereqs updates with
    | Error (`Capnp e) ->
        Format.eprintf "Capnp error: %a" Capnp_rpc.Error.pp e;
        Unix._exit 1
    | Error (`Remote e) ->
        Format.eprintf "Remote error: %s" e;
        Unix._exit 1
    | Ok () -> ()
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let help copts man_format cmds topic =
  match topic with
  | None -> `Help (`Pager, None) (* help about the program. *)
  | Some topic -> (
      let topics = "topics" :: "patterns" :: "environment" :: cmds in
      let conv, _ = Cmdliner.Arg.enum (List.rev_map (fun s -> (s, s)) topics) in
      match conv topic with
      | `Error e -> `Error (false, e)
      | `Ok t when t = "topics" ->
          List.iter print_endline topics;
          `Ok ()
      | `Ok t when List.mem t cmds -> `Help (man_format, Some t)
      | `Ok t ->
          let page = ((topic, 7, "", "", ""), [ `S topic; `P "Say something" ]) in
          `Ok (Cmdliner.Manpage.print man_format Format.std_formatter page))

open Cmdliner

let help_secs =
  [
    `S "MORE HELP";
    `P "Use $(mname) $(i,COMMAND) --help for help on a single command.";
    `Noblank;
    `P "Use $(mname) $(b,help patterns) for help on patch matching.";
    `Noblank;
    `P "Use $(mname) $(b,help environment) for help on environment variables.";
    `S Manpage.s_bugs;
    `P "Check bug reports at https://github.com/RyanGibb/eon.";
  ]

let copts cap_uri cap_uri_file env =
  let cap_uri =
    match cap_uri with Some c -> c | None -> Uri.of_string (Eio.Path.load Eio.Path.(Eio.Stdenv.fs env / cap_uri_file))
  in
  { cap_uri }

let copts_t =
  let docs = Manpage.s_common_options in
  let cap_uri =
    let doc =
      "Capability URI of the format capnp://sha-256:<hash>@address:port/<service-ID>. Takes priority over cap-file."
    in
    let i = Arg.info [ "cap" ] ~docv:"CAP" ~doc in
    Arg.(value @@ opt (some Capnp_rpc_unix.sturdy_uri) None i)
  in
  let cap_uri_file =
    let doc =
      "File path containing the capability URI of the format capnp://sha-256:<hash>@address:port/<service-ID>."
    in
    Arg.(value & opt string "root.cap" & info [ "cap-file" ] ~docv:"CAP_FILE" ~doc)
  in
  Term.(const copts $ cap_uri $ cap_uri_file)

let sdocs = Manpage.s_common_options

let cert_cmd =
  let email =
    let doc = "The email address to use for the ACME account." in
    Arg.(required & pos 0 (some string) None & info [] ~docv:"EMAIL" ~doc)
  in
  let domain =
    let doc = "The domain name to query." in
    Arg.(required & pos 1 (some (conv (Domain_name.of_string, Domain_name.pp))) None & info [] ~docv:"DOMAIN" ~doc)
  in
  let org =
    let doc = "The name of the organization requesting the certificate." in
    Arg.(value & opt string "" & info [ "org" ] ~docv:"ORGANIZATION" ~doc)
  in
  let cert_root =
    let doc = "Directory to store the certificates and keys in at path <cert-root>/<domain>/." in
    Arg.(value & opt string "certs" & info [ "cert-root" ] ~doc)
  in
  let doc = "Provision a certificate." in
  let man =
    [
      `S Manpage.s_description;
      `P "Provision a certificate and put the fullchain certificate and private key in cert-root.";
      `Blocks help_secs;
    ]
  in
  let info = Cmd.info "cert" ~doc ~sdocs ~man in
  Cmd.v info Term.(const cert $ copts_t $ email $ domain $ org $ cert_root)

let update_cmd =
  let domain =
    let doc = "The domain name to query." in
    Arg.(required & pos 0 (some (conv (Domain_name.of_string, Domain_name.pp))) None & info [] ~docv:"DOMAIN" ~doc)
  in
  let type_of_string_exn typ =
    match Dns.Rr_map.of_string typ with Ok t -> t | Error (`Msg e) -> raise (Invalid_argument e)
  in
  let prereq_of_string str =
    let open Cap.Domain in
    try
      match String.split_on_char ':' str with
      | [ "exists"; domain; typ ] -> Ok (Domain_name.of_string_exn domain, Exists (type_of_string_exn typ))
      | [ "exists-data"; domain; typ; value ] ->
          Ok (Domain_name.of_string_exn domain, Exists_data (type_of_string_exn typ, value))
      | [ "not-exists"; domain; typ ] -> Ok (Domain_name.of_string_exn domain, Not_exists (type_of_string_exn typ))
      | [ "name-inuse"; domain ] -> Ok (Domain_name.of_string_exn domain, Name_inuse)
      | [ "not-name-inuse"; domain ] -> Ok (Domain_name.of_string_exn domain, Not_name_inuse)
      | _ -> Error (`Msg "Invalid prerequisite format")
    with
    | Invalid_argument e -> Error (`Msg (Printf.sprintf "Error parsing prerequisite %s" e))
    | _ -> Error (`Msg "Error parsing prerequisite")
  in
  let prereq_to_string fmt =
    let open Cap.Domain in
    function
    | domain, Exists typ -> Format.fprintf fmt "exists:%s:%a" (Domain_name.to_string domain) Dns.Rr_map.ppk typ
    | domain, Exists_data (typ, value) ->
        Format.fprintf fmt "exists-data:%s:%a:%s" (Domain_name.to_string domain) Dns.Rr_map.ppk typ value
    | domain, Not_exists typ -> Format.fprintf fmt "not-exists:%s:%a" (Domain_name.to_string domain) Dns.Rr_map.ppk typ
    | domain, Name_inuse -> Format.fprintf fmt "name-inuse:%s" (Domain_name.to_string domain)
    | domain, Not_name_inuse -> Format.fprintf fmt "name-not-inuse:%s" (Domain_name.to_string domain)
  in
  let prereqs =
    let doc =
      "Specify a prerequisite. Formats include: 'exists:DOMAIN:TYPE', 'exists-data:DOMAIN:TYPE:VALUE', \
       'not-exists:DOMAIN:TYPE', 'name-inuse:DOMAIN', 'name-not-inuse:DOMAIN'."
    in
    Arg.(
      value
      & opt_all (Cmdliner.Arg.conv (prereq_of_string, prereq_to_string)) []
      & info [ "p"; "prerequisite" ] ~docv:"PREREQUISITE" ~doc)
  in
  let update_of_string str =
    let open Cap.Domain in
    try
      match String.split_on_char ':' str with
      | [ "remove"; domain; typ ] -> Ok (Domain_name.of_string_exn domain, Remove (type_of_string_exn typ))
      | [ "remove-all"; domain ] -> Ok (Domain_name.of_string_exn domain, Remove_all)
      | [ "remove-single"; domain; typ; value ] ->
          Ok (Domain_name.of_string_exn domain, Remove_single (type_of_string_exn typ, value))
      | [ "add"; domain; typ; value; ttl_str ] ->
          Ok (Domain_name.of_string_exn domain, Add (type_of_string_exn typ, value, Int32.of_string ttl_str))
      | _ -> Error (`Msg "Invalid update format")
    with
    | Invalid_argument e -> Error (`Msg (Printf.sprintf "Error parsing update: %s" e))
    | Failure _ -> Error (`Msg "TTL must be a valid integer")
  in
  let update_to_string fmt =
    let open Cap.Domain in
    function
    | domain, Remove typ -> Format.fprintf fmt "remove:%s:%a" (Domain_name.to_string domain) Dns.Rr_map.ppk typ
    | domain, Remove_all -> Format.fprintf fmt "remove-all:%s" (Domain_name.to_string domain)
    | domain, Remove_single (typ, value) ->
        Format.fprintf fmt "remove-single:%s:%a:%s" (Domain_name.to_string domain) Dns.Rr_map.ppk typ value
    | domain, Add (typ, value, ttl) ->
        Format.fprintf fmt "add:%s:%a:%s:%ld" (Domain_name.to_string domain) Dns.Rr_map.ppk typ value ttl
  in
  let updates =
    let doc =
      "Specify an update. Formats include remove:DOMAIN:TYPE, remove-all:DOMAIN, remove-single:DOMAIN:TYPE:VALUE, or \
       add:DOMAIN:TYPE:VALUE:TTL"
    in
    Arg.(
      value
      & opt_all (Cmdliner.Arg.conv (update_of_string, update_to_string)) []
      & info [ "u"; "update" ] ~docv:"UPDATE" ~doc)
  in
  let doc = "Udpate DNS records." in
  let man =
    [ `S Manpage.s_description; `P "Update DNS records with an interface based on RFC 2136."; `Blocks help_secs ]
  in
  let info = Cmd.info "update" ~doc ~sdocs ~man in
  Cmd.v info Term.(const update $ copts_t $ domain $ prereqs $ updates)

let help_cmd =
  let topic =
    let doc = "The topic to get help on. $(b,topics) lists the topics." in
    Arg.(value & pos 0 (some string) None & info [] ~docv:"TOPIC" ~doc)
  in
  let doc = "display help about capc" in
  let man = [ `S Manpage.s_description; `P "Prints help about capc."; `Blocks help_secs ] in
  let info = Cmd.info "help" ~doc ~man in
  Cmd.v info Term.(ret (const help $ copts_t $ Arg.man_format $ Term.choice_names $ topic))

let main_cmd =
  let doc = "An Eon client." in
  let man = help_secs in
  let info = Cmd.info "capc" ~version:"%%VERSION%%" ~doc ~sdocs ~man in
  let default = Term.(ret (const (fun _ -> `Help (`Pager, None)) $ copts_t)) in
  Cmd.group info ~default [ cert_cmd; update_cmd; help_cmd ]

let () = exit (Cmd.eval main_cmd)
