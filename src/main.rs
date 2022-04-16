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
        #[structopt(parse(try_from_str = parse_socket_addr))]
        server_addr: SocketAddr,

        addr: Ipv4Addr,

        #[structopt(short = "i", long = "tun-iface", default_value = "vpn0")]
        iface: String,

        #[structopt(long = "remote")]
        remotes: Option<Vec<Ipv4Addr>>,

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
            iced_vpn::server::server_main(bind_addr).await;
        }

        Command::Client {
            server_addr,
            addr,
            iface,
            remotes,
            stun_addr,
        } => {
            let remotes = remotes.unwrap_or_else(|| Vec::new());

            let mut client =
                iced_vpn::client::Client::connect(server_addr, &iface, addr, remotes, stun_addr)
                    .await;
            client.process().await;
        }
    }
}
