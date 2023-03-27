module Dns_ip : sig
  include Tcpip.Ip.S with type ipaddr = Ipaddr.t
end