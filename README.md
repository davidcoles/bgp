# bgp

A simple BGP library for originating /32 or /128 prefixes.

The primary use case is to provide route health injection functionality for a load balancer.

## Loopback BGP

I have found that it is possible to connect to a local BIRD instance
and advertise addresses for re-distribution into the network from
there. Here I connect to BIRD using multiprotocol extensions on the
loopback interface with 127.0.0.1 as my router ID and the loopback IP
addresses for both IPv4 and IPv6 next hop (BIRD will update these when
re-advertising):

`go run bgp.go -6 ::1 -m 65001 127.0.0.1 127.0.0.1`

Using the BIRD configuration below I can then connect to a router and
gain the benefits of using BFD. Global IPv6 addresses on the local
server and the router are needed for the IPv6 address to be
re-advertised successfully.

```
log syslog all;
protocol device {}
protocol bfd {}

filter vips {
    if net ~ [ 192.168.101.0/24{32,32} ] then accept; # accept /32 prefixes from 192.168.101.0/24
    if net ~ [ fd0b:2b0b:a7b8:1ee7:c0de::/80{128,128} ] then accept; # similar config for IPv6
    reject;
}

protocol bgp core {
    local    as 65001;
    neighbor as 65000;
    neighbor 10.12.34.56;
    ipv4 { export filter vips; import none; next hop self; };
    ipv6 { export filter vips; import none; next hop self; };
    bfd on;
}

protocol bgp lb {
    local    as 65001;  # iBGP - we could use eBGP if we specify 'multihop':
    neighbor as 65001;  # loopback address doesn't count as "directly connected"
    neighbor 127.0.0.1; # load balancer connects on the loopback interface
    passive;            # load balancer always inititates the connection
    ipv4 { export none; import all; };
    ipv6 { export none;	import all; };
}
```

If you get it working on other implementations then it would be great
to have more sample configurations here.
