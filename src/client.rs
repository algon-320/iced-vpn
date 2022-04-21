use etherparse::Ipv4Header;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::crypto;
use crate::tun::setup_tun;
use crate::{addresses_as_bytes, Message, MessageChan};

#[derive(Debug)]
struct Packet(Vec<u8>);

#[derive(Debug)]
struct IceAuth {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ufrag: String,
    pwd: String,
}

#[derive(Debug)]
struct IceCand {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    candidate: String,
}

pub struct Client {
    addr: Ipv4Addr,
    session_key: crypto::SessionKey,
    control: MessageChan<TcpStream>,
    tun: tokio_tun::Tun,

    channels: HashMap<
        Ipv4Addr,
        (
            UnboundedSender<Packet>,
            UnboundedSender<IceAuth>,
            UnboundedSender<IceCand>,
        ),
    >,
    from_agent: UnboundedReceiver<Packet>,
    local_auth_rx: UnboundedReceiver<IceAuth>,
    local_cand_rx: UnboundedReceiver<IceCand>,
}

impl Client {
    pub async fn connect(
        server_addr: SocketAddr,
        ifname: &str,
        addr: Ipv4Addr,
        remotes: Vec<Ipv4Addr>,
        stun_addr: SocketAddr,
    ) -> Self {
        let mut control = {
            let stream = TcpStream::connect(server_addr).await.expect("connect");
            MessageChan::new(stream)
        };

        log::info!("connected");

        // FIXME
        let netmask_bit: u8 = 24;
        let mtu: u16 = 1300;

        // FIXME
        let key = crypto::StaticKeyPair::from_pkcs8(format!("keys/{}.prv.der", addr)).unwrap();
        let server_pubkey = std::fs::read(format!("keys/{}.pub.der", server_addr.ip())).unwrap();

        let session_key = {
            let (priv_seed, pubseed) = crypto::generate_seed_pair();
            let seed = key.sign(&pubseed);

            let hello = Message::Hello { addr, seed };
            control.send(hello).await.expect("send");

            let hello_reply = control.recv().await.expect("recv");
            match hello_reply {
                Message::Hello { seed, .. } => {
                    let seed = seed.open(&server_pubkey).expect("verify");
                    crypto::SessionKey::client_derive(priv_seed, seed)
                }
                _ => panic!("unexpected"),
            }
        };

        log::info!("session key is ready");

        let tun = setup_tun(ifname, addr, netmask_bit, mtu).expect("tun device");
        log::info!("tun device is ready");

        let mut channels = HashMap::new();

        let (to_control, from_agent) = unbounded_channel::<Packet>();
        let (local_auth_tx, local_auth_rx) = unbounded_channel::<IceAuth>();
        let (local_cand_tx, local_cand_rx) = unbounded_channel::<IceCand>();

        for remote_addr in remotes {
            let local_addr = addr;

            let to_control = to_control.clone();
            let (to_agent, from_control) = unbounded_channel::<Packet>();

            let local_auth_tx = local_auth_tx.clone();
            let local_cand_tx = local_cand_tx.clone();
            let (remote_auth_tx, remote_auth_rx) = unbounded_channel::<IceAuth>();
            let (remote_cand_tx, remote_cand_rx) = unbounded_channel::<IceCand>();

            tokio::spawn(async move {
                peer_to_peer_connection(
                    stun_addr,
                    local_addr,
                    remote_addr,
                    to_control,
                    from_control,
                    local_auth_tx,
                    local_cand_tx,
                    remote_auth_rx,
                    remote_cand_rx,
                )
                .await
            });

            channels.insert(remote_addr, (to_agent, remote_auth_tx, remote_cand_tx));
        }

        Self {
            addr,
            session_key,
            control,
            tun,

            channels,
            from_agent,
            local_auth_rx,
            local_cand_rx,
        }
    }

    pub async fn process(&mut self) {
        let mtu = self.tun.mtu().expect("tun mtu");
        let mut buf_packet = vec![0u8; mtu as usize];

        loop {
            tokio::select! {
                res = self.control.recv() => {
                    let msg = res.expect("receive");
                    self.on_control_message(msg).await;
                }

                res = self.tun.recv(&mut buf_packet) => {
                    let nb = res.unwrap();
                    let packet = &buf_packet[..nb];
                    self.on_packet_received_from_tun(packet).await;
                }

                res = self.from_agent.recv() => {
                    if let Some(Packet(packet)) = res {
                        self.tun.send(&packet).await.expect("tun send");
                    }
                }

                res = self.local_auth_rx.recv() => {
                    if let Some(IceAuth { src, dst, ufrag, pwd }) = res {
                        let msg = Message::IceAuth {
                            src,
                            dst,
                            ufrag,
                            pwd,
                        };
                        self.control.send(msg).await.expect("send");
                    }
                }

                res = self.local_cand_rx.recv() => {
                    if let Some(IceCand { src, dst, candidate }) = res {
                        let msg = Message::IceCandidate {
                            src,
                            dst,
                            candidate,
                        };
                        self.control.send(msg).await.expect("send");
                    }
                }
            }
        }
    }

    async fn on_control_message(&mut self, msg: Message) {
        match msg {
            Message::IceAuth {
                src,
                dst,
                ufrag,
                pwd,
            } if dst == self.addr => {
                let remote_auth = IceAuth {
                    src,
                    dst,
                    ufrag,
                    pwd,
                };
                let remote_auth_tx = &self.channels.get(&src).expect("unknown peer").1;
                remote_auth_tx.send(remote_auth).expect("mpsc send");
            }

            Message::IceCandidate {
                src,
                dst,
                candidate,
            } if dst == self.addr => {
                let remote_cand = IceCand {
                    src,
                    dst,
                    candidate,
                };
                let remote_cand_tx = &self.channels.get(&src).expect("unknown peer").2;
                remote_cand_tx.send(remote_cand).expect("mpsc send");
            }

            Message::Data { src, dst, packet } if dst == self.addr => {
                let aad = addresses_as_bytes(src, dst);
                let packet = self.session_key.unseal(&aad, packet).expect("unseal");
                self.tun.send(&packet[..]).await.expect("send");
            }

            _ => {
                log::warn!("unexpected message: {:?}", msg);
            }
        }
    }

    async fn on_packet_received_from_tun(&mut self, packet: &[u8]) {
        let (ip_hdr, _payload) = match Ipv4Header::from_slice(packet) {
            Ok(hdr_payload) => hdr_payload,
            Err(err) => {
                log::debug!("ignored uninteresting packet: {}", err);
                return;
            }
        };

        let src = Ipv4Addr::from(ip_hdr.source);
        let dst = Ipv4Addr::from(ip_hdr.destination);
        log::debug!("send    {} bytes: {:?} --> {:?}", packet.len(), src, dst,);

        if let Some((to_agent, _, _)) = self.channels.get(&dst) {
            to_agent.send(Packet(packet.to_vec())).expect("send");
        } else {
            let aad = addresses_as_bytes(src, dst);
            let packet = self.session_key.seal(&aad, packet.to_vec()).expect("seal");
            let msg = Message::Data { src, dst, packet };
            self.control.send(msg).await.expect("send");
        }
    }
}

async fn peer_to_peer_connection(
    stun_addr: SocketAddr,
    local_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,

    to_control: UnboundedSender<Packet>,
    mut from_control: UnboundedReceiver<Packet>,
    local_auth_tx: UnboundedSender<IceAuth>,
    local_cand_tx: UnboundedSender<IceCand>,
    mut remote_auth_rx: UnboundedReceiver<IceAuth>,
    mut remote_cand_rx: UnboundedReceiver<IceCand>,
) {
    use std::sync::Arc;

    use webrtc_ice::{
        agent::agent_config::AgentConfig, agent::Agent, candidate::Candidate,
        network_type::NetworkType, udp_network::UDPNetwork, url::Url,
    };
    use webrtc_util::conn::Conn;

    let stun_url = Url::parse_url(&format!("stun:{}", stun_addr)).unwrap();
    let ice_agent = Agent::new(AgentConfig {
        urls: vec![stun_url],
        network_types: vec![NetworkType::Udp4],
        udp_network: UDPNetwork::Ephemeral(Default::default()),
        ..Default::default()
    })
    .await
    .expect("new agent");
    let ice_agent = Arc::new(ice_agent);

    let is_controling = local_addr < remote_addr;

    {
        let local_cand_tx = local_cand_tx.clone();
        ice_agent
            .on_candidate(Box::new(
                move |candidate: Option<Arc<dyn Candidate + Send + Sync>>| {
                    if let Some(candidate) = candidate {
                        log::info!("new candidate!");

                        let addr = candidate.address();
                        log::debug!("address = {}", addr);

                        let ty = candidate.candidate_type();
                        use webrtc_ice::candidate::CandidateType;
                        let ignore = match ty {
                            CandidateType::Host => {
                                if addr == local_addr.to_string() {
                                    log::warn!("ignore itself");
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        };

                        if !ignore {
                            let local_cand = IceCand {
                                src: local_addr,
                                dst: remote_addr,
                                candidate: candidate.marshal(),
                            };
                            local_cand_tx.send(local_cand).expect("cand_rx closed");
                        }
                    }
                    Box::pin(async move {})
                },
            ))
            .await;
    }

    let (auth_done_tx, auth_done_rx) = tokio::sync::oneshot::channel::<()>();
    {
        // Get the local auth details and send to remote peer
        let (local_ufrag, local_pwd) = ice_agent.get_local_user_credentials().await;

        let local_auth_tx = local_auth_tx.clone();
        let mut auth_done_rx = auth_done_rx;
        tokio::spawn(async move {
            let post_auth = || {
                log::info!("posting remote auth {}:{}", local_ufrag, local_pwd);
                let local_auth = IceAuth {
                    src: local_addr,
                    dst: remote_addr,
                    ufrag: local_ufrag.clone(),
                    pwd: local_pwd.clone(),
                };
                local_auth_tx.send(local_auth).unwrap();
            };

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
            loop {
                tokio::select! {
                    _ = interval.tick() => { post_auth(); }
                    _ = &mut auth_done_rx => { post_auth(); break; }
                }
            }
        });
    }

    {
        let ice_agent = ice_agent.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cand = remote_cand_rx.recv() => {
                        let IceCand { src, dst, candidate } = cand.unwrap();
                        assert_eq!(src, remote_addr);
                        assert_eq!(dst, local_addr);
                        use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
                        let c = unmarshal_candidate(&candidate).await.expect("unmarshal");
                        let c: Arc<dyn Candidate + Send + Sync + 'static> = Arc::new(c);
                        ice_agent.add_remote_candidate(&c).await.expect("add");
                    }
                }
            }
        });
    }

    let (remote_ufrag, remote_pwd) = {
        log::info!("waiting for remote auth");
        let IceAuth {
            src,
            dst,
            ufrag,
            pwd,
        } = remote_auth_rx.recv().await.unwrap();
        assert_eq!(src, remote_addr);
        assert_eq!(dst, local_addr);
        (ufrag, pwd)
    };

    log::info!("auth OK");
    let _ = auth_done_tx.send(());

    ice_agent.gather_candidates().await.unwrap();

    let conn: Arc<dyn Conn + Send + Sync> = {
        let (_cancel_tx, cancel_rx) = channel(1);
        if is_controling {
            log::info!("dialing ...");
            ice_agent
                .dial(cancel_rx, remote_ufrag, remote_pwd)
                .await
                .unwrap()
        } else {
            log::info!("accepting ...");
            ice_agent
                .accept(cancel_rx, remote_ufrag, remote_pwd)
                .await
                .unwrap()
        }
    };

    log::info!("p2p connection is ready");

    let mut buf = vec![0u8; 0x1000];

    // FIXME
    let key = crypto::StaticKeyPair::from_pkcs8(format!("keys/{}.prv.der", local_addr)).unwrap();
    let remote_pubkey = std::fs::read(format!("keys/{}.pub.der", remote_addr)).unwrap();

    let mut session_key = if is_controling {
        log::debug!("active role");

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
        log::debug!("passive role");

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

    loop {
        tokio::select! {
            res = conn.recv(&mut buf) => {
                let nb = res.unwrap();
                let msg: Message = bincode::deserialize(&buf[..nb]).expect("deserialize");
                match msg {
                    Message::Data { src, dst, packet } if src == remote_addr && dst == local_addr  => {
                        let aad = addresses_as_bytes(src, dst);
                        let bytes = session_key.unseal(&aad, packet).expect("unseal");
                        to_control.send(Packet(bytes)).unwrap();
                    }

                    _ => {
                        log::debug!("unexpected message");
                        continue;
                    }
                }
            }

            res = from_control.recv() => {
                log::debug!("send a packet through p2p connection");

                let Packet(packet) = res.unwrap();
                let aad = addresses_as_bytes(local_addr, remote_addr);
                let sealed_packet = session_key.seal(&aad, packet).expect("seal");
                let msg = Message::Data { src: local_addr, dst: remote_addr, packet: sealed_packet };

                let bytes = bincode::serialize(&msg).expect("serialize");
                conn.send(&bytes).await.expect("send");
            }
        }
    }
}
