let packet_callback ~net wake (question : Dns.Packet.Question.t) :
    Dns.Packet.reply option =
  let qname, _qtype = question in
  let ( let* ) = Option.bind in
  let* _, mac =
    List.find_opt (fun (name, _) -> Domain_name.equal name qname) wake
  in
  Format.fprintf Format.std_formatter "Resolution on %a wakes %a\n" Domain_name.pp
    qname Macaddr.pp mac;
  Format.print_flush ();
  Wol_eio.send ~net mac;
  None

let run zonefiles log_level address_strings port proto wake =
  Eio_main.run @@ fun env ->
  let addresses = Server_args.parse_addresses port address_strings in
  let log = Dns_log.get log_level Format.std_formatter in
  let rng ?_g length =
    let buf = Cstruct.create length in
    Eio.Flow.read_exact env#secure_random buf;
    Cstruct.to_string buf
  in
  let server_state =
    let trie, keys, _ = Zonefile.parse_zonefiles ~fs:env#fs zonefiles in
    Dns_server.Primary.create ~keys ~rng ~tsig_verify:Dns_tsig.verify
      ~tsig_sign:Dns_tsig.sign trie
  in
  let packet_callback = packet_callback ~net:env#net wake in
  Dns_server_eio.primary env proto (ref server_state) log addresses
    ~packet_callback

let () =
  let open Cmdliner in
  let open Server_args in
  let wake =
    let name_mac_of_string str =
      try
        match String.split_on_char '/' str with
        | [ name; mac ] ->
            Ok (Domain_name.of_string_exn name, Macaddr.of_string_exn mac)
        | _ ->
            Error
              (`Msg
                "Invalid domain name and MAC address pair, should be of form \
                 DOMAIN_NAME/MAC_ADDR.")
      with
      | Invalid_argument e ->
          Error (`Msg (Printf.sprintf "Error parsing domain name: %s" e))
      | Macaddr.Parse_error (e, _s) ->
          Error (`Msg (Printf.sprintf "Error parsing MAC address: %s" e))
    in
    let name_mac_to_string fmt (name, mac) =
      Format.fprintf fmt "%s/%s"
        (Domain_name.to_string name)
        (Macaddr.to_string mac)
    in
    let doc =
      "Specify a MAC address to wake on a resolution of a domain name via \
       Wake-on-LAN. Format should be of the form DOMAIN_NAME/MAC_ADDR."
    in
    Arg.(
      value
      & opt_all (Cmdliner.Arg.conv (name_mac_of_string, name_mac_to_string)) []
      & info [ "w"; "wake" ] ~docv:"WAKE" ~doc)
  in
  let cmd =
    let term =
      Term.(
        const run $ zonefiles $ log_level Dns_log.Level0 $ addresses $ port
        $ proto $ wake)
    in
    let info = Cmd.info "hibernia" ~man in
    Cmd.v info term
  in
  exit (Cmd.eval cmd)
