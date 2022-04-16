mod crypto;
mod error;
mod tun;

pub mod client;
pub mod server;

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};

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

use tokio::io::{AsyncReadExt, AsyncWriteExt};

enum ReaderState {
    ReadingSize,
    ReadingPayload { done: usize, pending: usize },
}
enum WriterState {
    WritingSize,
    WritingPayload { done: usize, pending: usize },
}

impl Default for ReaderState {
    fn default() -> Self {
        ReaderState::ReadingSize
    }
}
impl Default for WriterState {
    fn default() -> Self {
        WriterState::WritingSize
    }
}

async fn receive_message<R: AsyncRead + Unpin>(
    state: &mut ReaderState,
    buf: &mut Vec<u8>,
    reader: &mut R,
) -> Result<Message> {
    loop {
        match state {
            ReaderState::ReadingSize => {
                let size = reader.read_u64().await?;
                log::trace!("receive size = {}", size);
                *state = ReaderState::ReadingPayload {
                    done: 0,
                    pending: size as usize,
                };
                buf.resize(size as usize, 0u8);
            }

            ReaderState::ReadingPayload {
                mut done,
                mut pending,
            } => {
                let nb = reader.read(&mut buf[done..done + pending]).await?;
                done += nb;
                pending -= nb;
                log::trace!("done: {}, pending: {}", done, pending);
                if pending == 0 {
                    let msg = bincode::deserialize(&buf[..]).map_err(|_| Error::BrokenMessage)?;
                    *state = ReaderState::ReadingSize;
                    return Ok(msg);
                } else {
                    *state = ReaderState::ReadingPayload { done, pending };
                }
            }
        }
    }
}

async fn send_message<W: AsyncWrite + Unpin>(
    state: &mut WriterState,
    buf: &mut Vec<u8>,
    writer: &mut W,
    msg: Message,
) -> Result<()> {
    loop {
        match state {
            WriterState::WritingSize => {
                let size = bincode::serialized_size(&msg).expect("serialize");
                log::trace!("send size = {}", size);
                writer.write_u64(size).await?;

                buf.resize(size as usize, 0u8);
                let mut writer = &mut buf[..];
                bincode::serialize_into(&mut writer, &msg).expect("serialize");

                *state = WriterState::WritingPayload {
                    done: 0,
                    pending: size as usize,
                };
            }

            WriterState::WritingPayload {
                mut done,
                mut pending,
            } => {
                let nb = writer.write(&buf[done..done + pending]).await?;
                done += nb;
                pending -= nb;
                log::trace!("done: {}, pending: {}", done, pending);

                if pending == 0 {
                    writer.flush().await?;
                    *state = WriterState::WritingSize;
                    return Ok(());
                } else {
                    *state = WriterState::WritingPayload { done, pending };
                }
            }
        }
    }
}

/// Returns an bytes representation of the source and destination addresses.
fn addresses_as_bytes(src: Ipv4Addr, dst: Ipv4Addr) -> [u8; 8] {
    let s = src.octets();
    let d = dst.octets();
    [s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]]
}
