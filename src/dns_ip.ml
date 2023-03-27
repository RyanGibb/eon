
let src = Logs.Src.create "dns_ip" ~doc:"DNS IP"
module Log = (val Logs.src_log src : Logs.LOG)

module Dns_ip = struct
  type ipaddr = Ipaddr.t
  type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit

  let pp_ipaddr = Ipaddr.pp

  type t = {
    mono : Eio.Time.Mono.t;
    random : Eio.Flow.source;
  }

  let write t ?(fragment = true) ?(ttl = 38) ?src dst proto ?(size = 0) headerf bufs =
    ()

  let input t ~tcp ~udp ~default buf =
    ()

  let get_ip t = [Ipaddr.V4 Ipaddr.V4.any]

  let pseudoheader t ?src dst proto len =
    Cstruct.create 1

  let src t ~dst:_ = Ipaddr.V4 Ipaddr.V4.any

  let mtu t ~dst:_ = 1

  let disconnect _ = ()

end