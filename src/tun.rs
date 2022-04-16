use std::net::Ipv4Addr;

use crate::error::{Error, Result};

/// Opens a tun device named <ifname>
pub fn setup_tun(
    ifname: &str,
    addr: Ipv4Addr,
    netmask_bit: u8,
    mtu: u16,
) -> Result<tokio_tun::Tun> {
    let netmask = {
        let mut bits: u32 = 0;
        for _ in 0..netmask_bit {
            bits = (bits << 1) | 1;
        }
        for _ in 0..(32 - netmask_bit) {
            bits = (bits << 1) | 0;
        }
        bits
    };

    let tun = tokio_tun::TunBuilder::new()
        .name(ifname)
        .tap(false)
        .packet_info(false)
        .mtu(mtu as i32)
        .address(addr)
        .netmask(Ipv4Addr::from(netmask))
        .up()
        .try_build()
        .map_err(|err| Error::Setup {
            msg: err.to_string(),
        })?;

    Ok(tun)
}
