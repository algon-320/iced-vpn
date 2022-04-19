FROM rust:alpine
RUN apk update && apk add \
    alpine-sdk \
    bash \
    coturn \
    iptables \
    linux-headers

WORKDIR /root

RUN mkdir /root/vpn
COPY Cargo.toml /root/vpn/
COPY src /root/vpn/src
COPY genkey.sh pubkey.sh /root/vpn/
COPY docker/start-vpn.sh /root/

RUN cargo install --path /root/vpn --all-features --bin iced-vpn
