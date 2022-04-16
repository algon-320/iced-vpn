#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to setup tun device: {}", .msg)]
    Setup { msg: String },

    #[error("the message was broken")]
    BrokenMessage,

    #[error("private key is invalid (unsupported format)")]
    InvalidPrivateKeyFormat,

    #[error("invalid signature")]
    InvalidSignature,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
