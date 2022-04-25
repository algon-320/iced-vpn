use actix::prelude::*;
use bytes::Bytes;
use etherparse::Ipv4Header;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::client::ServerConnection;
use crate::error::{Error, Result};
use crate::message::PlainPacket;

/// Opens a tun device named <ifname>
fn setup_tun(ifname: &str, addr: Ipv4Addr, netmask_bit: u8, mtu: u16) -> Result<tokio_tun::Tun> {
    let netmask: u32 = {
        assert!(netmask_bit <= 32);
        let mut bits: u32 = ((1u64 << netmask_bit as u64) - 1) as u32;
        bits <<= 32 - netmask_bit;
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

pub struct TunDevice {
    addr: Ipv4Addr,
    tun: Arc<tokio_tun::Tun>,
}

impl Actor for TunDevice {
    type Context = Context<Self>;
}

impl Supervised for TunDevice {
    fn restarting(&mut self, _: &mut Self::Context) {
        println!("TunDevice restarting");
    }
}

// Outgoing
impl Handler<PlainPacket> for TunDevice {
    type Result = ();

    fn handle(&mut self, PlainPacket { packet, dst, .. }: PlainPacket, _ctx: &mut Self::Context) {
        if dst != self.addr {
            return;
        }

        let tun = self.tun.clone();
        Arbiter::current().spawn(async move {
            log::debug!("tun write {} bytes: {:?}", packet.len(), packet.as_ref());
            tun.send(&packet).await.expect("tun write");
        });
    }
}

impl TunDevice {
    pub fn start(
        ifname: &str,
        addr: Ipv4Addr,
        netmask_bit: u8,
        mtu: u16,
        to_server: Addr<ServerConnection>,
        _: &mut Context<Self>,
    ) -> Self {
        let tun = setup_tun(ifname, addr, netmask_bit, mtu).expect("tun device");
        let tun = Arc::new(tun);
        log::info!("tun device is ready");

        let task = Self::tun_reading(tun.clone(), to_server);
        Arbiter::current().spawn(task);

        TunDevice { addr, tun }
    }

    async fn tun_reading(tun: Arc<tokio_tun::Tun>, to_server: Addr<ServerConnection>) {
        let mut buf = vec![0_u8; 0x1000];
        loop {
            let n = tun.recv(&mut buf[..]).await.expect("tun read");
            let packet = &buf[..n];

            let (src, dst) = match Ipv4Header::from_slice(packet) {
                Ok((hdr, _)) => (hdr.source.into(), hdr.destination.into()),
                Err(err) => {
                    log::trace!("ignored uninteresting packet: {}", err);
                    continue;
                }
            };
            let plain_packet = PlainPacket {
                src,
                dst,
                packet: Bytes::copy_from_slice(packet),
            };
            dbg!(&plain_packet);

            // TODO: routing

            to_server.do_send(plain_packet);
        }
    }
}
