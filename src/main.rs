use std::net::{Ipv4Addr, SocketAddr};
use structopt::StructOpt;

fn parse_socket_addr(url: &str) -> std::io::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let mut iter = url.to_socket_addrs()?;
    iter.next().ok_or(std::io::Error::new(
        std::io::ErrorKind::Other,
        "cannot resolve".to_string(),
    ))
}

#[derive(Debug, StructOpt)]
enum Command {
    Server {
        #[structopt(short = "b", long = "bind", default_value = "0.0.0.0:31415", parse(try_from_str = parse_socket_addr))]
        bind_addr: SocketAddr,
    },

    Client {
        addr: Ipv4Addr,

        #[structopt(short = "i", long = "tun-iface", default_value = "vpn0")]
        iface: String,

        #[structopt(long = "p2p")]
        direct_peers: Option<Vec<Ipv4Addr>>,

        #[structopt(parse(try_from_str = parse_socket_addr))]
        server_addr: SocketAddr,

        #[structopt(long = "stun", default_value = "stun.l.google.com:19302", parse(try_from_str = parse_socket_addr))]
        stun_addr: SocketAddr,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let cmd = Command::from_args();
    log::debug!("cmd = {:?}", cmd);

    match cmd {
        Command::Server { bind_addr } => {
            use iced_vpn::server::Server;
            Server::new(bind_addr).listen().await;
        }

        Command::Client {
            addr,
            iface,
            direct_peers,
            server_addr,
            stun_addr,
        } => {
            let direct_peers = direct_peers.unwrap_or_else(|| Vec::new());

            use iced_vpn::client::{Client, ClientConfig};
            let conf = ClientConfig {
                addr,
                ifname: iface,
                direct_peers,
                server_addr,
                stun_addr,
            };
            let mut client = iced_vpn::client::Client::connect(config).await;
            client.process().await;
        }
    }
}
