use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_serde::{formats::SymmetricalBincode, SymmetricallyFramed};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// impl Sink<Bytes>
pub type FrameSink<AW> = FramedWrite<AW, LengthDelimitedCodec>;
pub fn new_frame_sink<AW>(writer: AW) -> FrameSink<AW>
where
    AW: AsyncWrite,
{
    FramedWrite::new(writer, LengthDelimitedCodec::default())
}

/// impl Sink<T>
pub type SerdeSink<T, S> = SymmetricallyFramed<S, T, SymmetricalBincode<T>>;
pub fn new_serde_sink<T, S>(frame_sink: S) -> SerdeSink<T, S>
where
    T: Serialize,
    S: Sink<Bytes, Error = std::io::Error>,
{
    SymmetricallyFramed::new(frame_sink, SymmetricalBincode::default())
}

/// impl Stream<Output = Result<BytesMut, LengthDelimitedCodecError>>
pub type FrameStream<AR> = FramedRead<AR, LengthDelimitedCodec>;
pub fn new_frame_stream<AR>(reader: AR) -> FrameStream<AR>
where
    AR: AsyncRead,
{
    FramedRead::new(reader, LengthDelimitedCodec::default())
}

/// impl Stream<Output = T>
pub type SerdeStream<T, S> = SymmetricallyFramed<S, T, SymmetricalBincode<T>>;
pub fn new_serde_stream<T, S>(frame_stream: S) -> SerdeStream<T, S>
where
    for<'a> T: Deserialize<'a>,
    S: Stream<Item = Result<BytesMut, std::io::Error>>,
{
    SerdeStream::new(frame_stream, SymmetricalBincode::default())
}
