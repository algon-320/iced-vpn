#!/bin/bash
set -euf -o pipefail

BRIDGE_NAME="container-br"

function address-inet() {
    echo "10.255.0.$1"
}

function delete-veth() {
    devname=$1
    (ip link | grep $devname) && ip link delete devname type veth
}

function stop-container() {
    cname=$1
    docker stop "$cname" || true
}

stop-container "lan1-router"
stop-container "lan1-host"
stop-container "lan2-router"
stop-container "lan2-host"
stop-container "server"

ip link set down dev $BRIDGE_NAME
ip link delete dev $BRIDGE_NAME type bridge

iptables -t filter -D FORWARD -o $BRIDGE_NAME -j ACCEPT
iptables -t filter -D FORWARD -i $BRIDGE_NAME ! -o $BRIDGE_NAME -j ACCEPT
iptables -t nat -D POSTROUTING ! -o $BRIDGE_NAME -s "$(address-inet 0)/24" -j MASQUERADE

delete-veth 'r1-br'
delete-veth 'br-r1'
delete-veth 'r2-br'
delete-veth 'br-r2'
delete-veth 'sv-br'
delete-veth 'br-sv'
delete-veth 'h1-r1'
delete-veth 'r1-h1'
delete-veth 'h2-r2'
delete-veth 'r2-h2'
