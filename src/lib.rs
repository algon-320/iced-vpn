mod crypto;
mod error;
mod message;
mod tun;

pub mod client;
pub mod server;

use std::net::Ipv4Addr;

/// Returns an bytes representation of the source and destination addresses.
fn addresses_as_bytes(src: Ipv4Addr, dst: Ipv4Addr) -> [u8; 8] {
    let s = src.octets();
    let d = dst.octets();
    [s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]]
}
