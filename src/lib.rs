mod crypto;
mod error;
mod tun;

pub mod client;
pub mod server;

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::error::Result;

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    /// A message to establish a connection (from a peer to the server).
    Hello {
        addr: Ipv4Addr,
        seed: crypto::Signed<crypto::PubSeed>,
    },

    IceAuth {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ufrag: String,
        pwd: String,
    },

    /// A message to pass ICE candidates
    IceCandidate {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        candidate: String,
    },

    /// A message to transmit IP packet
    Data {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        packet: crypto::Sealed<Vec<u8>>,
    },
}

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_serde::{formats::SymmetricalBincode, SymmetricallyFramed};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

struct MessageChan<Stream>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    inner: SymmetricallyFramed<
        Framed<Stream, LengthDelimitedCodec>,
        Message,
        SymmetricalBincode<Message>,
    >,
}

impl<S> MessageChan<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        let codec = LengthDelimitedCodec::new();
        let length_delimited = Framed::new(stream, codec);
        let inner = SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());
        Self { inner }
    }

    pub async fn send(&mut self, msg: Message) -> Result<()> {
        self.inner.send(msg).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Message> {
        let msg = self.inner.next().await.unwrap()?;
        Ok(msg)
    }
}

/// Returns an bytes representation of the source and destination addresses.
fn addresses_as_bytes(src: Ipv4Addr, dst: Ipv4Addr) -> [u8; 8] {
    let s = src.octets();
    let d = dst.octets();
    [s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]]
}
