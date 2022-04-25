use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::crypto;

#[derive(Debug, Serialize, Deserialize, actix::Message)]
#[rtype(result = "()")]
pub struct SealedPacket {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub packet: crypto::Sealed<Bytes>,
}

#[derive(Debug, Serialize, Deserialize, actix::Message)]
#[rtype(result = "()")]
pub struct PlainPacket {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub packet: Bytes,
}

#[derive(Debug, Serialize, Deserialize, actix::Message)]
#[rtype(result = "()")]
pub struct IceAuth {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ufrag: String,
    pub pwd: String,
}

#[derive(Debug, Serialize, Deserialize, actix::Message)]
#[rtype(result = "()")]
pub struct IceCand {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub candidate: String,
}

#[derive(Debug, Serialize, Deserialize, actix::Message)]
#[rtype(result = "()")]
pub enum Message {
    /// A message to establish a connection (from a peer to the server).
    Hello {
        addr: Ipv4Addr,
        seed: crypto::Signed<crypto::PubSeed>,
    },

    /// A message to exchange ICE authorization via the server
    IceAuth(IceAuth),

    /// A message to exchange ICE candidates via the server
    IceCand(IceCand),

    /// A message to transmit IP packet
    Data(SealedPacket),
}

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_serde::{formats::SymmetricalBincode, SymmetricallyFramed};
use tokio_util::codec::LengthDelimitedCodec;

use futures::{SinkExt, StreamExt};

pub struct MessageChannel<Stream>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    inner: SymmetricallyFramed<
        tokio_util::codec::Framed<Stream, LengthDelimitedCodec>,
        Message,
        SymmetricalBincode<Message>,
    >,
}

impl<S> MessageChannel<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        let codec = LengthDelimitedCodec::new();
        let length_delimited = tokio_util::codec::Framed::new(stream, codec);
        let inner = SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());
        Self { inner }
    }

    pub async fn send(&mut self, msg: Message) -> crate::error::Result<()> {
        self.inner.send(msg).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> crate::error::Result<Message> {
        let msg = self.inner.next().await.unwrap()?;
        Ok(msg)
    }
}
