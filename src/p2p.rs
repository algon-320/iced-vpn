use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use webrtc_ice::{
    agent::{agent_config::AgentConfig, Agent as IceAgent},
    candidate::{candidate_base::unmarshal_candidate, Candidate},
    network_type::NetworkType,
    udp_network::UDPNetwork,
    url::Url,
};
use webrtc_util::conn::Conn;

use crate::addresses_as_bytes;
use crate::client::{Outgoing as TcpOutgoing, ServerConnection};
use crate::crypto;
use crate::message::{IceAuth, IceCand, Message, PlainPacket, SealedPacket};
use crate::tun::TunDevice;

use actix::prelude::*;

#[derive(Debug, actix::Message)]
#[rtype(result = "()")]
struct Incoming(SealedPacket);

#[derive(Debug, actix::Message)]
#[rtype(result = "()")]
struct Outgoing(PlainPacket);

enum ConnectionState {
    Waiting,
    Preparing,
    Connected {
        session_key: Box<crypto::SessionKey>,
        conn: Arc<dyn Conn>,
    },
}

pub struct PeerConnection {
    local_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    state: ConnectionState,
    agent: Arc<IceAgent>,
    is_controlling: bool,

    to_tundev: Addr<TunDevice>,
    #[allow(unused)]
    to_server: Addr<ServerConnection>,
}

impl PeerConnection {
    pub async fn new(
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
        stun_addr: SocketAddr,
        to_tundev: Addr<TunDevice>,
        to_server: Addr<ServerConnection>,
        _: &mut Context<Self>,
    ) -> Self {
        let stun_url = Url::parse_url(&format!("stun:{}", stun_addr)).unwrap();
        let agent = IceAgent::new(AgentConfig {
            urls: vec![stun_url],
            network_types: vec![NetworkType::Udp4],
            udp_network: UDPNetwork::Ephemeral(Default::default()),
            ..Default::default()
        })
        .await
        .expect("new agent");
        let agent = Arc::new(agent);

        // report local auth
        let (local_ufrag, local_pwd) = agent.get_local_user_credentials().await;
        let local_auth = Message::IceAuth(IceAuth {
            src: local_addr,
            dst: remote_addr,
            ufrag: local_ufrag.clone(),
            pwd: local_pwd.clone(),
        });
        to_server
            .send(TcpOutgoing(local_auth))
            .await
            .expect("local auth to sever");

        let is_controlling = local_addr < remote_addr;

        Self {
            local_addr,
            remote_addr,
            state: ConnectionState::Waiting,
            agent,
            is_controlling,

            to_tundev,
            to_server,
        }
    }
}

impl Actor for PeerConnection {
    type Context = Context<Self>;
}

impl Supervised for PeerConnection {}

impl Handler<IceAuth> for PeerConnection {
    type Result = ();
    fn handle(&mut self, remote_auth: IceAuth, ctx: &mut Self::Context) -> Self::Result {
        match self.state {
            ConnectionState::Waiting => {}
            _ => return,
        }

        let IceAuth { src, dst, .. } = remote_auth;
        assert_eq!(src, self.remote_addr);
        assert_eq!(dst, self.local_addr);

        self.state = ConnectionState::Preparing;

        let task = establish_connection(self.is_controlling, self.agent.clone(), remote_auth)
            .into_actor(self)
            .map(|(conn, session_key), act, ctx| {
                act.state = ConnectionState::Connected {
                    session_key,
                    conn: conn.clone(),
                };

                let laddr = act.local_addr;
                let raddr = act.remote_addr;
                let task = receive_packets(laddr, raddr, conn, ctx.address());
                ctx.spawn(task.into_actor(act));
            });
        ctx.spawn(task);
    }
}

impl Handler<IceCand> for PeerConnection {
    type Result = ();

    fn handle(&mut self, remote_cand: IceCand, _ctx: &mut Self::Context) -> Self::Result {
        let IceCand {
            src,
            dst,
            candidate,
        } = remote_cand;
        assert_eq!(src, self.remote_addr);
        assert_eq!(dst, self.local_addr);

        let agent = self.agent.clone();
        Arbiter::current().spawn(async move {
            let c = unmarshal_candidate(&candidate).await.expect("unmarshal");
            let c: Arc<dyn Candidate + Send + Sync + 'static> = Arc::new(c);
            agent.add_remote_candidate(&c).await.expect("add");
        });
    }
}

impl Handler<Incoming> for PeerConnection {
    type Result = ();

    fn handle(&mut self, Incoming(sealed_packet): Incoming, _ctx: &mut Self::Context) {
        let key = match &mut self.state {
            ConnectionState::Connected { session_key, .. } => session_key,
            _ => return,
        };

        let SealedPacket { src, dst, packet } = sealed_packet;
        assert_eq!(src, self.remote_addr);
        assert_eq!(dst, self.local_addr);

        let aad = addresses_as_bytes(src, dst);
        let packet = key.unseal(&aad, packet).expect("verify");
        let plain_packet = PlainPacket { src, dst, packet };

        self.to_tundev.do_send(plain_packet);
    }
}

impl Handler<Outgoing> for PeerConnection {
    type Result = actix::ResponseFuture<()>;

    fn handle(
        &mut self,
        Outgoing(plain_packet): Outgoing,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (key, conn) = match &mut self.state {
            ConnectionState::Connected { session_key, conn } => (session_key, conn.clone()),
            _ => return Box::pin(async {}),
        };

        let PlainPacket { src, dst, packet } = plain_packet;
        let aad = addresses_as_bytes(src, dst);
        let packet = key.seal(&aad, packet).expect("seal");

        Box::pin(async move {
            conn.send(packet.as_bytes()).await.unwrap();
        })
    }
}

async fn establish_connection(
    is_controlling: bool,
    agent: Arc<IceAgent>,
    remote_auth: IceAuth,
) -> (Arc<dyn Conn>, Box<crypto::SessionKey>) {
    let IceAuth {
        src: remote_addr,
        dst: local_addr,
        ufrag,
        pwd,
    } = remote_auth;

    agent.gather_candidates().await.expect("gather candidate");

    let (_cancel_tx, cancel) = tokio::sync::mpsc::channel(1);
    let conn: Arc<dyn Conn> = if is_controlling {
        log::info!("dialing ...");
        agent.dial(cancel, ufrag, pwd).await.unwrap()
    } else {
        log::info!("accepting ...");
        agent.accept(cancel, ufrag, pwd).await.unwrap()
    };

    log::info!("p2p connection is ready");

    let mut buf = vec![0u8; 0x1000];

    let key = crypto::StaticKeyPair::from_pkcs8(format!("keys/{}.prv.der", local_addr)).unwrap();
    let remote_pubkey = std::fs::read(format!("keys/{}.pub.der", remote_addr)).unwrap();

    let session_key = if is_controlling {
        log::debug!("controlling role");

        let (priv_seed, pubseed) = crypto::generate_seed_pair();
        let seed = key.sign(&pubseed);

        log::debug!("sending a Hello message");
        let hello = Message::Hello {
            addr: local_addr,
            seed,
        };
        let bytes = bincode::serialize(&hello).expect("serialize");
        conn.send(&bytes).await.expect("send");

        log::debug!("waiting for a Hello (reply) message");
        let nb = conn.recv(&mut buf[..]).await.expect("recv");
        let msg: Message = bincode::deserialize(&buf[..nb]).expect("deserialize");
        match msg {
            Message::Hello { seed, addr } if addr == remote_addr => {
                let seed = seed.open(&remote_pubkey).expect("verify");
                crypto::SessionKey::client_derive(priv_seed, seed)
            }
            _ => panic!("unexpected"),
        }
    } else {
        log::debug!("controlled role");

        log::debug!("waiting for a Hello message");
        let nb = conn.recv(&mut buf).await.unwrap();
        let msg: Message = bincode::deserialize(&buf[..nb]).expect("deserialize");
        let signed_seed = match msg {
            Message::Hello { addr, seed } if addr == remote_addr => seed,
            _ => panic!("unexpected"),
        };
        let remote_seed = signed_seed.open(&remote_pubkey).expect("verify");

        let (priv_seed, pub_seed) = crypto::generate_seed_pair();
        let session_key = crypto::SessionKey::server_derive(priv_seed, remote_seed);

        let signed_seed = key.sign(&pub_seed);
        let reply = Message::Hello {
            seed: signed_seed,
            addr: local_addr,
        };

        log::debug!("sending a Hello (reply) message");
        let bytes = bincode::serialize(&reply).expect("serialize");
        conn.send(&bytes).await.expect("send");

        session_key
    };

    log::info!("p2p session key is ready");
    (conn, Box::new(session_key))
}

async fn receive_packets(
    local_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    conn: Arc<dyn Conn>,
    addr: Addr<PeerConnection>,
) {
    // TODO: larger than max packet size
    let mut buf = vec![0u8; 0x1000];
    loop {
        let size = conn.recv(&mut buf).await.expect("recv");
        let ciphertext = &buf[..size];
        let packet = unsafe { crypto::Sealed::<bytes::Bytes>::from_bytes(ciphertext.to_vec()) };
        let sealed_packet = SealedPacket {
            src: remote_addr,
            dst: local_addr,
            packet,
        };
        addr.do_send(Incoming(sealed_packet));
    }
}
