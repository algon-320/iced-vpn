use futures::{SinkExt, StreamExt};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{tcp, TcpStream};

use crate::addresses_as_bytes;
use crate::crypto;
use crate::io;
use crate::message::{Message, PlainPacket, SealedPacket};
use crate::tun::TunDevice;

#[derive(Debug, actix::Message)]
#[rtype(result = "()")]
pub struct Incoming(pub Message);

#[derive(Debug, actix::Message)]
#[rtype(result = "()")]
pub struct Outgoing(pub Message);

use actix::prelude::*;

use actix::io::{SinkWrite, WriteHandler};

type MessageSinkTcp = io::SerdeSink<Message, io::FrameSink<tcp::OwnedWriteHalf>>;
type MessageStreamTcp = io::SerdeSink<Message, io::FrameStream<tcp::OwnedReadHalf>>;

enum ConnectionState {
    Preparing,
    Connected {
        message_writer: SinkWrite<Message, MessageSinkTcp>,
        session_key: Box<crypto::SessionKey>,
    },
}

pub struct ServerConnection {
    vpn_addr: Ipv4Addr,
    server_addr: SocketAddr,
    state: ConnectionState,

    to_tundev: Addr<TunDevice>,
}

impl Actor for ServerConnection {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.initialize(ctx);
    }
}

impl Supervised for ServerConnection {
    fn restarting(&mut self, ctx: &mut Self::Context) {
        self.state = ConnectionState::Preparing;
        self.initialize(ctx);
    }
}

impl ServerConnection {
    pub fn start(
        vpn_addr: Ipv4Addr,
        server_addr: SocketAddr,
        to_tundev: Addr<TunDevice>,
        _: &mut Context<Self>,
    ) -> Self {
        Self {
            vpn_addr,
            server_addr,
            state: ConnectionState::Preparing,
            to_tundev,
        }
    }

    fn initialize(&mut self, ctx: &mut Context<Self>) {
        let task = Self::establish_server_connection(self.vpn_addr, self.server_addr);
        let fut = task
            .into_actor(self)
            .map(|(sink, stream, session_key), act, ctx| {
                let stream = stream.map(|msg| msg.map(Incoming));
                Self::add_stream(stream, ctx);

                let connected = ConnectionState::Connected {
                    message_writer: SinkWrite::new(sink, ctx),
                    session_key,
                };
                act.state = connected;
            });
        ctx.wait(fut);
    }

    async fn establish_server_connection(
        vpn_addr: Ipv4Addr,
        server_addr: SocketAddr,
    ) -> (MessageSinkTcp, MessageStreamTcp, Box<crypto::SessionKey>) {
        let stream = TcpStream::connect(server_addr).await.expect("connect");
        let (rhalf, whalf) = stream.into_split();

        let mut msg_stream: io::SerdeStream<Message, _> =
            io::new_serde_stream(io::new_frame_stream(rhalf));

        let mut msg_sink: io::SerdeSink<Message, _> = io::new_serde_sink(io::new_frame_sink(whalf));

        let path = format!("keys/{}.prv.der", vpn_addr);
        let key = crypto::StaticKeyPair::from_pkcs8(path).unwrap();
        let (priv_seed, pubseed) = crypto::generate_seed_pair();
        let signed_seed = key.sign(&pubseed);

        let hello = Message::Hello {
            addr: vpn_addr,
            seed: signed_seed,
        };
        msg_sink.send(hello).await.expect("sink closed");

        let path = format!("keys/{}.pub.der", server_addr.ip());
        let server_pubkey = std::fs::read(path).unwrap();

        let server_pubseed = loop {
            let msg = msg_stream.next().await.unwrap().expect("recv");
            match msg {
                Message::Hello { seed, .. } => break seed.open(&server_pubkey).expect("verify"),
                _ => continue,
            }
        };

        let session_key = crypto::SessionKey::client_derive(priv_seed, server_pubseed);

        (msg_sink, msg_stream, Box::new(session_key))
    }
}

// Handler for `Message` from the server
impl StreamHandler<Result<Incoming, std::io::Error>> for ServerConnection {
    fn handle(&mut self, res: Result<Incoming, std::io::Error>, _ctx: &mut Self::Context) {
        let msg = match res {
            Err(io_err) => {
                log::error!("tcp incoming error: {}", io_err);
                return;
            }
            Ok(Incoming(msg)) => msg,
        };

        let key = match &mut self.state {
            ConnectionState::Connected { session_key, .. } => session_key,
            _ => {
                return;
            }
        };

        log::debug!("{:?}", msg);

        match msg {
            Message::Data(SealedPacket { src, dst, packet }) => {
                let aad = addresses_as_bytes(src, dst);
                let packet = key.unseal(&aad, packet).expect("unseal");
                let plain_packet = PlainPacket { src, dst, packet };
                self.to_tundev.do_send(plain_packet);
            }

            Message::IceAuth(_remote_auth) => {
                // send to PeerConnection
                todo!()
            }

            Message::IceCand(_remote_cand) => {
                // send to PeerConnection
                todo!()
            }

            Message::Hello { .. } => {}
        }
    }
}

impl WriteHandler<std::io::Error> for ServerConnection {}

impl Handler<Outgoing> for ServerConnection {
    type Result = ();
    fn handle(&mut self, Outgoing(msg): Outgoing, _ctx: &mut Self::Context) {
        let writer = match &mut self.state {
            ConnectionState::Connected { message_writer, .. } => message_writer,
            _ => return,
        };
        writer.write(msg).unwrap();
    }
}

impl Handler<PlainPacket> for ServerConnection {
    type Result = ();
    fn handle(&mut self, PlainPacket { src, dst, packet }: PlainPacket, _ctx: &mut Self::Context) {
        if src != self.vpn_addr {
            return;
        }

        let (key, writer) = match &mut self.state {
            ConnectionState::Preparing => {
                return;
            }
            ConnectionState::Connected {
                session_key,
                message_writer,
            } => (session_key, message_writer),
        };

        let aad = addresses_as_bytes(src, dst);
        let packet = key.seal(&aad, packet).expect("seal");
        let msg = Message::Data(SealedPacket { src, dst, packet });
        writer.write(msg).unwrap();
    }
}

pub struct ClientConfig {
    pub addr: Ipv4Addr,
    pub ifname: String,
    pub direct_peers: Vec<Ipv4Addr>,

    pub stun_addr: SocketAddr,
    pub server_addr: SocketAddr,
}

pub struct Client(());

impl Client {
    pub async fn connect(
        ClientConfig {
            addr,
            ifname,
            direct_peers,
            server_addr,
            stun_addr,
        }: ClientConfig,
    ) -> Self {
        // FIXME
        let netmask_bit: u8 = 24;
        let mtu: u16 = 1300;

        let mut ctx_con = Context::new();
        let mut ctx_tun = Context::new();
        let con = ServerConnection::start(addr, server_addr, ctx_tun.address(), &mut ctx_con);
        let tun = TunDevice::start(
            &ifname,
            addr,
            netmask_bit,
            mtu,
            ctx_con.address(),
            &mut ctx_tun,
        );
        let to_tundev = ctx_tun.run(tun);
        let to_server = ctx_con.run(con);

        for remote_addr in direct_peers {
            let local_addr = addr;
            let to_server = to_server.clone();
            let to_tundev = to_tundev.clone();

            use crate::p2p::PeerConnection;
            let mut ctx = Context::new();
            let act = PeerConnection::new(
                local_addr,
                remote_addr,
                stun_addr,
                to_tundev,
                to_server,
                &mut ctx,
            )
            .await;
            let _addr = ctx.run(act);
            // TODO: save addr
        }

        Self(())
    }

    pub async fn process(&mut self) {
        let () = std::future::pending().await;
    }
}
