let zonefiles =
  Cmdliner.Arg.(
    value & opt_all string []
    & info [ "z"; "zonefile" ] ~docv:"ZONEFILE_PATHS" ~doc:"Zonefile path.")

let logging =
  Cmdliner.Arg.(
    value & opt int 1
    & info [ "l"; "log-level" ] ~docv:"LOG_LEVEL" ~doc:"Log level.")

let port =
  Cmdliner.Arg.(
    value & opt int 53 & info [ "p"; "port" ] ~docv:"PORT" ~doc:"Port.")

let addresses =
  let doc =
    "IP addresses to bind too.\n\
    \      \n\
    \    By default `in6addr_any` '::' is used. If IPv4-mapped IPv6 (RFC3493) \
     is not\n\
    \    supported, e.g. on OpenBSD, the user will need to specify an IPv4 \
     address\n\
    \    in order to serve IPv4 traffic, e.g. `-a 127.0.0.1 -a '::'`.\n\
    \    \n\
    \    A can be specified, e.g. with `[::]:5053`, otherwise the default\n\
    \    `port` is used.\n\n\
    \    NB names, e.g. `localhost`, are not supported."
  in
  Cmdliner.Arg.(
    (* :: is IPv6 local *)
    value & opt_all string [ "::" ]
    & info [ "a"; "address" ] ~docv:"ADDRESSES" ~doc)

let tcp =
  let doc = "Whether to use TCP." in
  Cmdliner.Arg.(value & opt bool true & info [ "t"; "tcp" ] ~docv:"TCP" ~doc)

let udp =
  let doc = "Whether to use UDP." in
  Cmdliner.Arg.(value & opt bool true & info [ "u"; "udp" ] ~docv:"UDP" ~doc)
