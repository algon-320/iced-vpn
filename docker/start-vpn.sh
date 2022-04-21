#!/bin/bash
set -euf -o pipefail

server="10.255.0.4:31415"
stun_server="10.255.0.4:3478"

case "${1:-}" in
    "server")
        RUST_LOG=debug iced-vpn server -b "$server"
        ;;
    "host1")
        RUST_LOG=debug iced-vpn client "10.20.30.1" --p2p "10.20.30.2" "$server" --stun "$stun_server"
        ;;
    "host2")
        RUST_LOG=debug iced-vpn client "10.20.30.2" --p2p "10.20.30.1" "$server" --stun "$stun_server"
        ;;
esac

