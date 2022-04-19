#!/bin/bash
set -euf -o pipefail

IMAGE_NAME="iced-vpn"

if ! (docker images | grep "$IMAGE_NAME") || [ "${1:-x}" = "--rebuild" ]; then
    docker build . -t "$IMAGE_NAME"
fi

function docker-pid() {
    docker inspect --format '{{.State.Pid}}' "$@"
}

function run-container() {
    name=$1
    docker run --privileged \
        --name "$name" --hostname "$name" \
        --rm -itd --net=none \
        -v "$PWD/test-keys:/root/keys"\
        "$IMAGE_NAME" /bin/bash
}

function address-inet() {
    echo "10.255.0.$1"
}
function address-lan1() {
    echo "10.1.0.$1"
}
function address-lan2() {
    echo "10.2.0.$1"
}
function address-vpn() {
    echo "10.20.30.$1"
}

## Setup router and server

BRIDGE_NAME="container-br"

function setup-inet() {
    cname=$1
    host_to_bridge=$2
    bridge_to_host=$3
    addr_host=$4
    addr_bridge=$5

    ip link add $host_to_bridge type veth peer name $bridge_to_host

    ip link set up dev $bridge_to_host
    ip link set master $BRIDGE_NAME dev $bridge_to_host

    ip link set netns $(docker-pid $cname) dev $host_to_bridge
    docker exec $cname ip link set up dev $host_to_bridge
    docker exec $cname ip addr add "$addr_host/24" dev $host_to_bridge
    docker exec $cname ip route add '0.0.0.0/0' via $addr_bridge dev $host_to_bridge
}

addr_inet=$(address-inet 0)
addr_inet_bridge=$(address-inet 1)
addr_inet_router1=$(address-inet 2)
addr_inet_router2=$(address-inet 3)
addr_inet_server=$(address-inet 4)

run-container 'lan1-router'
run-container 'lan2-router'
run-container 'server'

ip link add $BRIDGE_NAME type bridge
ip link set up dev $BRIDGE_NAME
ip addr add "$addr_inet_bridge/24" dev $BRIDGE_NAME

setup-inet 'lan1-router' 'r1-br' 'br-r1' $addr_inet_router1 $addr_inet_bridge
setup-inet 'lan2-router' 'r2-br' 'br-r2' $addr_inet_router2 $addr_inet_bridge
setup-inet 'server'      'sv-br' 'br-sv' $addr_inet_server  $addr_inet_bridge

iptables -t filter -A FORWARD -o $BRIDGE_NAME -j ACCEPT
iptables -t filter -A FORWARD -i $BRIDGE_NAME ! -o $BRIDGE_NAME -j ACCEPT
iptables -t nat -A POSTROUTING ! -o $BRIDGE_NAME -s "$addr_inet/24" -j MASQUERADE

echo 1 > /proc/sys/net/ipv4/ip_forward

## Add hosts to each LAN

function setup-lan() {
    cname_router=$1
    cname_host=$2
    router_to_bridge=$3
    host_to_router=$4
    router_to_host=$5
    addr_net=$6
    addr_router=$7
    addr_host=$8
    addr_inet_router=$9

    ip link add $host_to_router type veth peer name $router_to_host
    ip link set netns $(docker-pid $cname_router) dev $router_to_host
    docker exec $cname_router ip link set up dev $router_to_host
    docker exec $cname_router ip addr add "$addr_router/24" dev $router_to_host

    # emulate full-cone NAT
    docker exec $cname_router iptables -t nat -A POSTROUTING -o $router_to_bridge -j SNAT --to-source $addr_inet_router
    docker exec $cname_router iptables -t nat -A PREROUTING  -i $router_to_bridge -j DNAT --to-destination $addr_host

    ip link set netns $(docker-pid $cname_host) dev $host_to_router
    docker exec $cname_host ip link set up dev $host_to_router
    docker exec $cname_host ip addr add "$addr_host/24" dev $host_to_router
    docker exec $cname_host ip route add '0.0.0.0/0' via $addr_router dev $host_to_router
}

addr_lan1=$(address-lan1 0)
addr_router1=$(address-lan1 1)
addr_host1=$(address-lan1 2)
addr_lan2=$(address-lan2 0)
addr_router2=$(address-lan2 1)
addr_host2=$(address-lan2 2)

run-container 'lan1-host'
run-container 'lan2-host'

setup-lan 'lan1-router' 'lan1-host' 'r1-br' 'h1-r1' 'r1-h1' $addr_lan1 $addr_router1 $addr_host1 $addr_inet_router1
setup-lan 'lan2-router' 'lan2-host' 'r2-br' 'h2-r2' 'r2-h2' $addr_lan2 $addr_router2 $addr_host2 $addr_inet_router2

## Generate keys

docker exec 'server' sh -c "/root/vpn/genkey.sh > keys/${addr_inet_server}.prv.der"
docker exec 'server' sh -c "/root/vpn/pubkey.sh < keys/${addr_inet_server}.prv.der > keys/${addr_inet_server}.pub.der"

addr_vpn_host1=$(address-vpn 1)
addr_vpn_host2=$(address-vpn 2)

docker exec 'lan1-host' sh -c "/root/vpn/genkey.sh > keys/${addr_vpn_host1}.prv.der"
docker exec 'lan1-host' sh -c "/root/vpn/pubkey.sh < keys/${addr_vpn_host1}.prv.der > keys/${addr_vpn_host1}.pub.der"

docker exec 'lan2-host' sh -c "/root/vpn/genkey.sh > keys/${addr_vpn_host2}.prv.der"
docker exec 'lan2-host' sh -c "/root/vpn/pubkey.sh < keys/${addr_vpn_host2}.prv.der > keys/${addr_vpn_host2}.pub.der"

## Start STUN server
docker exec 'server' sh -c "turnserver -S > /dev/null &"
