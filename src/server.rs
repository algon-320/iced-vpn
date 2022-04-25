use bytes::Bytes;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::addresses_as_bytes;
use crate::crypto;
use crate::message::{IceAuth, IceCand, Message, MessageChannel, SealedPacket};

#[derive(Debug)]
enum InternalMessage {
    NewPeer(Ipv4Addr, ToPeer),
    Packet(Ipv4Addr, Ipv4Addr, Bytes),
    IceCandidate(Ipv4Addr, Ipv4Addr, String),
    IceAuth(Ipv4Addr, Ipv4Addr, String, String),
}

type ToPeer = UnboundedSender<InternalMessage>;
type FromPeer = UnboundedReceiver<InternalMessage>;
type ToRouter = UnboundedSender<InternalMessage>;
type FromRouter = UnboundedReceiver<InternalMessage>;

async fn process(
    server_key_path: &str,
    to_router: ToRouter,
    client_conn: TcpStream,
    sock_addr: SocketAddr,
) {
    log::info!("new client on {}", sock_addr);

    let mut client_conn = MessageChannel::new(client_conn);

    let server_key = crypto::StaticKeyPair::from_pkcs8(server_key_path).unwrap();

    let (peer_addr, mut session_key) = {
        let msg = client_conn.recv().await.expect("client_conn receive");
        let (addr, signed_seed) = match msg {
            Message::Hello { addr, seed } => (addr, seed),
            _ => panic!("unexpected message"),
        };
        // FIXME
        let peer_pubkey = std::fs::read(format!("keys/{}.pub.der", addr)).unwrap();
        let peer_seed = signed_seed.open(&peer_pubkey).expect("signature invalid");

        let (priv_seed, pub_seed) = crypto::generate_seed_pair();
        let session_key = crypto::SessionKey::server_derive(priv_seed, peer_seed);

        let signed_seed = server_key.sign(&pub_seed);
        let reply = Message::Hello {
            seed: signed_seed,
            addr, // FIXME
        };

        client_conn.send(reply).await.expect("client_conn send");

        (addr, session_key)
    };

    log::info!("{}: session key is ready", peer_addr);

    let (to_peer, mut from_router): (ToPeer, FromRouter) = unbounded_channel();
    to_router
        .send(InternalMessage::NewPeer(peer_addr, to_peer))
        .expect("router dead");

    // Start processing

    loop {
        tokio::select! {
            msg = from_router.recv() => {
                let msg = msg.expect("rotuer dead");
                match msg {
                    InternalMessage::Packet(src, dst, packet) if dst == peer_addr => {
                        let aad = addresses_as_bytes(src, dst);
                        let sealed = session_key.seal(&aad, packet).expect("seal");
                        let msg = Message::Data(SealedPacket { src, dst, packet: sealed });
                        client_conn.send(msg).await.expect("send");
                    }

                    InternalMessage::IceCandidate(src, dst, candidate) if dst == peer_addr => {
                        log::debug!("IceCandidate {{ {}, {}, {} }}", src, dst, candidate);
                        let msg = Message::IceCand(IceCand { src, dst, candidate });
                        client_conn.send(msg).await.expect("send");
                    }
                    InternalMessage::IceAuth(src, dst, ufrag, pwd) if dst == peer_addr => {
                        log::debug!("IceAuth {{ {}, {}, {}, {} }}", src, dst, ufrag, pwd);
                        let msg = Message::IceAuth(IceAuth { src, dst, ufrag, pwd });
                        client_conn.send(msg).await.expect("send");
                    }

                    otherwise => {
                        log::warn!("unexpected message from the router: {:?}", otherwise);
                    }
                }
            }

            res = client_conn.recv() => {
                match res {
                    Ok(Message::Data(SealedPacket { src, dst, packet })) => {
                        let aad = addresses_as_bytes(src, dst);
                        let packet = session_key.unseal(&aad, packet).expect("unseal");
                        let msg = InternalMessage::Packet(src, dst, packet);
                        to_router.send(msg).expect("router dead");
                    }

                    Ok(Message::IceCand(IceCand {src, dst, candidate }))  => {
                        let msg = InternalMessage::IceCandidate(src, dst, candidate);
                        to_router.send(msg).expect("router dead");
                    }
                    Ok(Message::IceAuth(IceAuth {src, dst, ufrag, pwd }))  => {
                        let msg = InternalMessage::IceAuth(src, dst, ufrag, pwd);
                        to_router.send(msg).expect("router dead");
                    }

                    Ok(msg) => {
                        log::warn!("unexpected message peer={}: {:?}", peer_addr, msg);
                    }

                    Err(err) => {
                        log::error!("{}", err);
                        return;
                    }
                }
            }
        }
    }
}

async fn router(mut from_peer: FromPeer) {
    use std::collections::HashMap;
    let mut channels: HashMap<Ipv4Addr, ToPeer> = HashMap::new();

    while let Some(msg) = from_peer.recv().await {
        match msg {
            InternalMessage::NewPeer(addr, to_peer) => {
                channels.insert(addr, to_peer);
            }

            InternalMessage::Packet(src, dst, packet) => {
                if let Some(chan) = channels.get(&dst) {
                    log::info!("packet: {} --> {}", src, dst);
                    let msg = InternalMessage::Packet(src, dst, packet);
                    chan.send(msg).expect("router -> peer");
                } else {
                    log::error!("unknown peer: {}", dst);
                }
            }

            InternalMessage::IceCandidate(src, dst, cands) => {
                if let Some(chan) = channels.get(&dst) {
                    let msg = InternalMessage::IceCandidate(src, dst, cands);
                    chan.send(msg).expect("router -> peer");
                } else {
                    log::error!("unknown peer: {}", dst);
                }
            }
            InternalMessage::IceAuth(src, dst, ufrag, pwd) => {
                if let Some(chan) = channels.get(&dst) {
                    let msg = InternalMessage::IceAuth(src, dst, ufrag, pwd);
                    chan.send(msg).expect("router -> peer");
                } else {
                    log::error!("unknown peer: {}", dst);
                }
            }
        }
    }
}

pub struct Server {
    bind_addr: SocketAddr,
}

impl Server {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self { bind_addr }
    }

    pub async fn listen(&self) {
        server_main(self.bind_addr).await
    }
}

async fn server_main(bind_addr: SocketAddr) {
    log::info!("listening on {}", bind_addr);
    let listener = TcpListener::bind(bind_addr).await.expect("bind");

    let (to_router, from_peer): (ToRouter, FromPeer) = unbounded_channel();

    tokio::spawn(async move { router(from_peer).await });

    let server_key_path = format!("keys/{}.prv.der", bind_addr.ip());

    while let Ok((stream, addr)) = listener.accept().await {
        let to_router = to_router.clone();
        let server_key_path = server_key_path.clone();
        tokio::spawn(async move { process(&server_key_path, to_router, stream, addr).await });
    }
}
