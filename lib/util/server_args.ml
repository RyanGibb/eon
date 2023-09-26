open Cmdliner

let zonefiles =
  Arg.(
    value & opt_all string []
    & info [ "z"; "zonefile" ] ~docv:"ZONEFILE_PATHS" ~doc:"Zonefile paths.")

let logging_default default =
  let doc = "Log level for DNS packets. See the LOGGING section." in
  Arg.(
    value & opt int default & info [ "l"; "log-level" ] ~docv:"LOG_LEVEL" ~doc)

let logging = logging_default 1

let port =
  let doc =
    "Port to bind on. By default 53 is used. See the BINDING section."
  in
  Arg.(value & opt int 53 & info [ "p"; "port" ] ~docv:"PORT" ~doc)

let addresses =
  let doc =
    "Socket addresses to bind too. By default `in6addr_any` ('::') is used. \
     See the BINDING section."
  in
  Arg.(
    (* :: is IPv6 local *)
    value & opt_all string [ "::" ]
    & info [ "a"; "address" ] ~docv:"ADDRESSES" ~doc)

let parse_addresses port addressStrings =
  List.map
    (fun ip ->
      match Ipaddr.with_port_of_string ~default:port ip with
      | Ok (ip, p) ->
          let eioIp = Ipaddr.to_octets ip |> Eio.Net.Ipaddr.of_raw in
          (eioIp, p)
      | Error (`Msg msg) ->
          Format.fprintf Format.err_formatter "Error parsing address '%s': %s"
            ip msg;
          Format.pp_print_flush Format.err_formatter ();
          exit 1)
    addressStrings

let no_tcp =
  let doc = "Whether to disable binding TCP sockets to ADDRESSES." in
  Arg.(value & flag & info [ "t"; "no-tcp" ] ~docv:"TCP" ~doc)

let no_udp =
  let doc = "Whether to disable binding UDP sockets to ADDRESSES." in
  Arg.(value & flag & info [ "u"; "no-udp" ] ~docv:"TCP" ~doc)

let man =
  let help_secs =
    [
      `S Manpage.s_options;
      `S "LOGGING";
      `Pre
        "Log levels are defined by the LOG_LEVEL option as one of these \
         possible values:\n\
        \    0 - No logging\n\
        \    1 - Log query id, question, and anwer\n\
        \    2 - Log all fields of DNS packets\n\
        \    3 - Log hex dumps of DNS packets\n\
         A level specified outside of this range will default to the closest.";
      `S "BINDING";
      `P
        "The socket(s) the server binds too can be configured with the \
         ADDRESSES and PORT options. This allows different IP addresses and \
         ports to be used. Specifying IP addresses can be useful for \
         restricting the network interfaces to listen on, as localhost listens \
         on all interfaces by default";
      `P
        "If IPv4-mapped IPv6 (RFC3493) is not supported, e.g. on OpenBSD, the \
         user will need to additionally specify an IPv4 address in order to \
         serve IPv4 traffic, e.g. '-a 127.0.0.1 -a '::''.";
      `P
        "A port can be sepecified as defined in RFC4038 Section 5.1, e.g. \
         '[::]:53' or '127.0.0.1::53', otherwise the default PORT is used.";
      `P
        "Note that names as might be used by `getaddrinfo`, e.g. 'localhost', \
         are not supported.";
      `S Manpage.s_bugs;
      `P "Check bug reports at https://github.com/RyanGibb/aeon/issues.";
    ]
  in
  [
    `S Manpage.s_description;
    `P "Prints help about darcs commands and other subjects…";
    `Blocks help_secs;
  ]
