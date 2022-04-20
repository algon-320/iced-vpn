# iced-vpn

- L3 VPN
- peer-to-peer connection by using ICE/STUN protocol

**DISCLAIMER: THIS IS A TOY PROJECT. DO NOT USE THIS UNDER ANY SECURITY SENSITIVE CIRCUMSTANCES.**

## Docker Example

The following network will be configured in this example.
```
 10.255.0.1
[container-bridge]----------------[server]
    |     |             10.255.0.4
    |     |
    |     +---------------------+
    |                           | 
    |                           |
    |10.255.0.2                 |10.255.0.3
[lan1-router] (NAT)         [lan2-router] (NAT)
    |10.1.0.1                   |10.2.0.1
    |                           |
    |                           |
    |10.1.0.2                   |10.2.0.2
[lan1-host] <=============> [lan2-host]
      10.20.30.1       10.20.30.2
```

### Build image and start/stop containers
```
$ ./docker/up.sh    # setup 5 containers
$ ./docker/down.sh  # stop all containers
```

### Start VPN

For server:
```
$ docker attach server
# ./start-vpn server
```

For host 1 (10.20.30.1):
```
$ docker attach lan1-host
# ./start-vpn host1
```

For host 2 (10.20.30.2):
```
$ docker attach lan2-host
# ./start-vpn host2
```

### Test the connection
On Host 1:
```
$ docker exec -it lan1-host /bin/bash
# ip addr show dev vpn0
2: vpn0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1300 qdisc fq_codel state UNKNOWN qlen 500
    link/[65534]
    inet 10.20.30.1/24 scope global vpn0
       valid_lft forever preferred_lft forever
# ping 10.20.30.2
PING 10.20.30.2 (10.20.30.2): 56 data bytes
64 bytes from 10.20.30.2: seq=0 ttl=64 time=1.408 ms
64 bytes from 10.20.30.2: seq=1 ttl=64 time=1.971 ms
64 bytes from 10.20.30.2: seq=2 ttl=64 time=1.590 ms
^C
--- 10.20.30.2 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 1.408/1.656/1.971 ms
```

