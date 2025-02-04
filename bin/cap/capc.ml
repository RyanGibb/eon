type copts = { cap_uri : Uri.t }

let get_name copts_env =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  let run_client cap =
    match Cap.Domain.get_name cap with
    | Error (`Capnp e) ->
        Format.eprintf "Capnp error: %a%!" Capnp_rpc.Error.pp e;
        Unix._exit 1
    | Error (`Remote e) ->
        Format.eprintf "Remote error: %s%!" e;
        Unix._exit 1
    | Ok name ->
        Printf.printf "%s\n%!" name;
        Unix._exit 0
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let cert copts_env email domains org cert_dir exit_when_renewed =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  let domain =
    match domains with
    | [] -> raise (Invalid_argument "Must specify at least one domain.")
    | domain :: _ -> domain
  in
  let run_client cap =
    (* callback for provisioned cert *)
    Capnp_rpc.Capability.with_ref
      (Cap.Cert_callback.local (fun result ->
           match result with
           | Error (`Capnp e) ->
               Format.eprintf "Capnp error: %a%!" Capnp_rpc.Error.pp e;
               Unix._exit 1
           | Error (`Remote msg) ->
               Printf.eprintf "Remote error: %s%!" msg;
               Unix._exit 1
           | Ok (fullchain, key, renewed) -> (
               match X509.Certificate.decode_pem_multiple fullchain with
               | Error (`Msg msg) ->
                   Printf.eprintf "Failed to decode cert %s%!" msg;
                   Unix._exit 1
               | Ok (cert :: chain) -> (
                   let write_pem filepath pem =
                     Eio.Path.save ~create:(`Or_truncate 0o640) filepath pem
                   in
                   let ( / ) = Eio.Path.( / ) in
                   let cert_dir =
                     match cert_dir with
                     | Some d -> env#fs / d
                     | None -> env#fs / "certs" / Domain_name.to_string domain
                   in
                   Eio.Path.mkdirs ~exists_ok:true ~perm:0o750 cert_dir;
                   write_pem (cert_dir / "key.pem") key;
                   write_pem (cert_dir / "fullchain.pem") fullchain;
                   write_pem (cert_dir / "cert.pem")
                     (X509.Certificate.encode_pem cert);
                   write_pem (cert_dir / "chain.pem")
                     (X509.Certificate.encode_pem_multiple chain);
                   match renewed with
                   | false ->
                       Printf.printf "Updated certificate for %s\n%!"
                         (Domain_name.to_string domain)
                   | true ->
                       Eio.Path.save ~create:(`Or_truncate 0o640)
                         (cert_dir / "renewed") "";
                       Printf.printf "Renewed certificate for %s\n%!"
                         (Domain_name.to_string domain);
                       if exit_when_renewed then Unix._exit 0)
               | _ ->
                   Printf.eprintf "Failed to get chain from %s%!" fullchain;
                   Unix._exit 1)))
    @@ fun callback ->
    match Cap.Domain.cert cap ~email ~org domains callback with
    | Error (`Capnp e) -> Format.eprintf "%a" Capnp_rpc.Error.pp e
    | Ok () -> ()
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let delegate copts_env subdomain cap_root =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
  let sturdy_ref = Capnp_rpc_unix.Vat.import_exn client_vat cap_uri in
  let run_client cap =
    match Cap.Domain.get_name cap with
    | Error (`Capnp e) ->
        Format.eprintf "Capnp error: %a%!" Capnp_rpc.Error.pp e;
        Unix._exit 1
    | Error (`Remote e) ->
        Format.eprintf "Remote error: %s%!" e;
        Unix._exit 1
    | Ok name -> name
  in
  let domain = Capnp_rpc_unix.with_cap_exn sturdy_ref run_client in
  let run_client cap =
    let delegated_cap = Cap.Domain.delegate cap subdomain in
    let delegated_cap_uri = Capnp_rpc.Persistence.save_exn delegated_cap in
    let file =
      Eio.Path.(
        env#fs / cap_root
        / (Domain_name.to_string subdomain ^ "." ^ domain ^ ".cap"))
    in
    Eio.Path.save ~create:(`Or_truncate 0o600) file
      (Uri.to_string delegated_cap_uri);
    let _, filepath = file in
    Printf.printf "Wrote capability to %s\n%!" filepath;
    Unix._exit 0
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let update copts_env prereqs updates =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env @@ fun () ->
  let copts = copts_env env in
  let cap_uri = copts.cap_uri in
  let sturdy_ref =
    let client_vat = Capnp_rpc_unix.client_only_vat ~sw env#net in
    Capnp_rpc_unix.Vat.import_exn client_vat cap_uri
  in
  let run_client cap =
    match Cap.Domain.update cap prereqs updates with
    | Error (`Capnp e) ->
        Format.eprintf "Capnp error: %a" Capnp_rpc.Error.pp e;
        Unix._exit 1
    | Error (`Remote e) ->
        Format.eprintf "Remote error: %s" e;
        Unix._exit 1
    | Ok () -> Unix._exit 0
  in
  Capnp_rpc_unix.with_cap_exn sturdy_ref run_client

let help _copts man_format cmds topic =
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
      | `Ok _t ->
          let page =
            ((topic, 7, "", "", ""), [ `S topic; `P "Say something" ])
          in
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

let copts cap_uri_file env =
  let cap_uri =
    Uri.of_string (Eio.Path.load Eio.Path.(Eio.Stdenv.fs env / cap_uri_file))
  in
  { cap_uri }

let copts_t =
  let _docs = Manpage.s_common_options in
  let cap_uri_file =
    let doc =
      "File path containing the domain capability URI of the format \
       capnp://sha-256:<hash>@address:port/<service-ID>."
    in
    Arg.(required & pos 0 (some string) None & info [] ~docv:"CAP_FILE" ~doc)
  in
  Term.(const copts $ cap_uri_file)

let sdocs = Manpage.s_common_options

let get_name_cmd =
  let doc = "Get the name for which this capability is authorative for." in
  let info = Cmd.info "get-name" ~doc ~sdocs in
  Cmd.v info Term.(const get_name $ copts_t)

let cert_cmd =
  let email =
    let doc = "The email address to use for the ACME account." in
    Arg.(required & pos 1 (some string) None & info [] ~docv:"EMAIL" ~doc)
  in
  let domains =
    let doc = "Domains to provision certificates for." in
    Arg.(
      value
      & opt_all (conv (Domain_name.of_string, Domain_name.pp)) []
      & info [ "d"; "domain" ] ~docv:"DOMAIN" ~doc)
  in
  let org =
    let doc = "The name of the organization requesting the certificate." in
    Arg.(
      value & opt (some string) None & info [ "org" ] ~docv:"ORGANIZATION" ~doc)
  in
  let cert_dir =
    let doc =
      "Directory to store the certificates and keys in. Defaults to \
       ./certs/<domain>."
    in
    Arg.(value & opt (some string) None & info [ "cert-dir" ] ~doc)
  in
  let exit_when_renewed =
    let doc = "Whether to exit once a certificate is renewed." in
    Arg.(value & flag & info [ "exit-when-renewed" ] ~doc)
  in
  let doc = "Provision a certificate." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Provision a certificate and put the fullchain certificate and private \
         key in cert-root.";
      `Blocks help_secs;
    ]
  in
  let info = Cmd.info "cert" ~doc ~sdocs ~man in
  Cmd.v info
    Term.(
      const cert $ copts_t $ email $ domains $ org $ cert_dir
      $ exit_when_renewed)

let delegate_cmd =
  let subdomain =
    let doc = "Subdomain to delegate a capability for." in
    Arg.(
      required
      & pos 1 (some (conv (Domain_name.of_string, Domain_name.pp))) None
      & info [] ~docv:"DOMAIN" ~doc)
  in
  let cap_root =
    let doc = "Directory to store the capability in." in
    Arg.(value & opt string "" & info [ "cap-dir" ] ~doc)
  in
  let doc = "Delegate a subdomain." in
  let man =
    [ `S Manpage.s_description; `P "Delegate a subdomain."; `Blocks help_secs ]
  in
  let info = Cmd.info "delegate" ~doc ~sdocs ~man in
  Cmd.v info Term.(const delegate $ copts_t $ subdomain $ cap_root)

let update_cmd =
  let open Dns in
  let type_of_string_exn typ =
    match Rr_map.of_string typ with
    | Ok t -> t
    | Error (`Msg e) -> raise (Invalid_argument e)
  in
  let parse_record ?(ttl = 0l) k v =
    (* TODO support more RRs *)
    match type_of_string_exn k with
    | K (Cname) -> Rr_map.B (Cname, (ttl, Domain_name.of_string_exn v))
    | K (A) -> Rr_map.B (A, (ttl, Ipaddr.V4.Set.singleton @@ Ipaddr.V4.of_string_exn v))
    | K (Aaaa) -> Rr_map.B (Aaaa, (ttl, Ipaddr.V6.Set.singleton @@ Ipaddr.V6.of_string_exn v))
    | K (Txt) -> Rr_map.B (Txt, (ttl, Rr_map.Txt_set.singleton v))
    | K (Ns) -> Rr_map.B (Ns, (ttl, Domain_name.Host_set.singleton (Domain_name.host_exn (Domain_name.of_string_exn v))))
    | k -> raise (Invalid_argument (Fmt.str "Can't parse %a" Dns.Rr_map.ppk k))
  in
  let print_record : type a. a Rr_map.key -> a -> int32 * string =
    fun k v ->
    (* TODO support more RRs *)
    match k, v with
    | Cname, (ttl, cname) -> ttl, Domain_name.to_string cname
    | A, (ttl, a) -> ttl, Ipaddr.V4.to_string (Ipaddr.V4.Set.choose a)
    | Aaaa, (ttl, aaaa) -> ttl, Ipaddr.V6.to_string (Ipaddr.V6.Set.choose aaaa)
    | Txt, (ttl, txt) -> ttl, Rr_map.Txt_set.choose txt
    | Ns, (ttl, ns) -> ttl, Domain_name.to_string (Domain_name.Host_set.choose ns)
    | k, _ -> raise (Invalid_argument (Fmt.str "Can't print %a" Dns.Rr_map.ppk (K k)))
  in
  let prereq_of_string str =
    let open Dns.Packet.Update in
    try
      match String.split_on_char '|' str with
      | [ "exists"; domain; typ ] ->
          Ok (Domain_name.of_string_exn domain, Exists (type_of_string_exn typ))
      | [ "exists"; domain; typ; value ] ->
          Ok
            ( Domain_name.of_string_exn domain,
              Exists_data (parse_record typ value) )
      | [ "not-exists"; domain; typ ] ->
          Ok
            ( Domain_name.of_string_exn domain,
              Not_exists (type_of_string_exn typ) )
      | [ "name-inuse"; domain ] ->
          Ok (Domain_name.of_string_exn domain, Name_inuse)
      | [ "not-name-inuse"; domain ] ->
          Ok (Domain_name.of_string_exn domain, Not_name_inuse)
      | _ -> Error (`Msg "Invalid prerequisite format")
    with
    | Invalid_argument e ->
        Error (`Msg (Printf.sprintf "Error parsing prerequisite %s" e))
    | _ -> Error (`Msg "Error parsing prerequisite")
  in
  let prereq_to_string fmt =
    let open Dns.Packet.Update in
    function
    | domain, Exists typ ->
        Format.fprintf fmt "exists|%s|%a"
          (Domain_name.to_string domain)
          Dns.Rr_map.ppk typ
    | domain, Exists_data (Dns.Rr_map.B (typ, v)) ->
        let _ttl, value = print_record typ v in
        Format.fprintf fmt "exists|%s|%a|%s"
          (Domain_name.to_string domain)
          Dns.Rr_map.ppk (K typ) value
    | domain, Not_exists typ ->
        Format.fprintf fmt "not-exists|%s|%a"
          (Domain_name.to_string domain)
          Dns.Rr_map.ppk typ
    | domain, Name_inuse ->
        Format.fprintf fmt "name-inuse|%s" (Domain_name.to_string domain)
    | domain, Not_name_inuse ->
        Format.fprintf fmt "name-not-inuse|%s" (Domain_name.to_string domain)
  in
  let prereqs =
    let doc =
      "Specify a prerequisite. Formats include: 'exists|DOMAIN|TYPE', \
       'exists|DOMAIN|TYPE|VALUE', 'not-exists|DOMAIN|TYPE', \
       'name-inuse|DOMAIN', 'name-not-inuse|DOMAIN'."
    in
    Arg.(
      value
      & opt_all (Cmdliner.Arg.conv (prereq_of_string, prereq_to_string)) []
      & info [ "p"; "prerequisite" ] ~docv:"PREREQUISITE" ~doc)
  in
  let update_of_string str =
    let open Dns.Packet.Update in
    try
      match String.split_on_char '|' str with
      | [ "remove"; domain; typ ] ->
          Ok (Domain_name.of_string_exn domain, Remove (type_of_string_exn typ))
      | [ "remove"; domain ] -> Ok (Domain_name.of_string_exn domain, Remove_all)
      | [ "remove"; domain; typ; value ] ->
          Ok
            ( Domain_name.of_string_exn domain,
              Remove_single (parse_record typ value) )
      | [ "add"; domain; typ; value; ttl_str ] ->
          let ttl = Int32.of_string ttl_str in
          Ok
            ( Domain_name.of_string_exn domain,
              Add (parse_record ~ttl typ value) )
      | _ -> Error (`Msg "Invalid update format")
    with
    | Invalid_argument e ->
        Error (`Msg (Printf.sprintf "Error parsing update: %s" e))
    | Failure _ -> Error (`Msg "TTL must be a valid integer")
  in
  let update_to_string fmt =
    let open Dns.Packet.Update in
    function
    | domain, Remove typ ->
        Format.fprintf fmt "remove|%s|%a"
          (Domain_name.to_string domain)
          Dns.Rr_map.ppk typ
    | domain, Remove_all ->
        Format.fprintf fmt "remove|%s" (Domain_name.to_string domain)
    | domain, Remove_single (Dns.Rr_map.B (typ, v)) ->
        let _ttl, value = print_record typ v in
        Format.fprintf fmt "remove|%s|%a|%s"
          (Domain_name.to_string domain)
          Dns.Rr_map.ppk (K typ) value
    | domain, Add (Dns.Rr_map.B (typ, v)) ->
        let ttl, value = print_record typ v in
        Format.fprintf fmt "add|%s|%a|%s|%ld"
          (Domain_name.to_string domain)
          Dns.Rr_map.ppk (K typ) value ttl
  in
  let updates =
    let doc =
      "Specify an update. Formats include remove|DOMAIN|TYPE, remove|DOMAIN, \
       remove|DOMAIN|TYPE|VALUE, or add|DOMAIN|TYPE|VALUE|TTL"
    in
    Arg.(
      value
      & opt_all (Cmdliner.Arg.conv (update_of_string, update_to_string)) []
      & info [ "u"; "update" ] ~docv:"UPDATE" ~doc)
  in
  let doc = "Update DNS records." in
  let man =
    [
      `S Manpage.s_description;
      `P "Update DNS records with an interface based on RFC 2136.";
      `Blocks help_secs;
    ]
  in
  let info = Cmd.info "update" ~doc ~sdocs ~man in
  Cmd.v info Term.(const update $ copts_t $ prereqs $ updates)

let help_cmd =
  let topic =
    let doc = "The topic to get help on. $(b,topics) lists the topics." in
    Arg.(value & pos 0 (some string) None & info [] ~docv:"TOPIC" ~doc)
  in
  let doc = "display help about capc" in
  let man =
    [
      `S Manpage.s_description; `P "Prints help about capc."; `Blocks help_secs;
    ]
  in
  let info = Cmd.info "help" ~doc ~man in
  Cmd.v info
    Term.(
      ret (const help $ copts_t $ Arg.man_format $ Term.choice_names $ topic))

let main_cmd =
  let doc = "An Eon client." in
  let man = help_secs in
  let info = Cmd.info "capc" ~version:"%%VERSION%%" ~doc ~sdocs ~man in
  let default = Term.(ret (const (fun _ -> `Help (`Pager, None)) $ copts_t)) in
  Cmd.group info ~default
    [ get_name_cmd; cert_cmd; delegate_cmd; update_cmd; help_cmd ]

let () = exit (Cmd.eval main_cmd)
