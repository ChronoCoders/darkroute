use quiethop_crypto::cell::CellError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("http client build: {0}")]
    HttpClientBuild(reqwest::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("authority returned status {0}: {1}")]
    AuthorityStatus(u16, String),
    #[error("authority response missing required field {0}")]
    MissingField(&'static str),
    #[error("authority response invalid: {0}")]
    InvalidResponse(String),
    #[error("authority returned a malformed RSA public key: {0}")]
    InvalidPubkey(String),
    #[error("blind token verification failed (token^e mod n != m)")]
    BlindVerifyFailed,
    #[error("authority returned a blinded signature that exceeds the modulus")]
    BlindOversized,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid server name {0:?}")]
    InvalidServerName(String),
    #[error("invalid endpoint {0:?}: {1}")]
    InvalidEndpoint(String, String),
    #[error("crypto: {0}")]
    Noise(#[from] quiethop_crypto::noise::NoiseError),
    #[error(transparent)]
    Registry(#[from] quiethop_crypto::registry::RegistryError),
    #[error("no path available: {0}")]
    NoPath(crate::path::NoPathReason),
    #[error("layer: {0}")]
    Layer(#[from] quiethop_crypto::layer::LayerError),
    #[error("cell: {0}")]
    Cell(#[from] CellError),
    #[error("circuit handshake: unexpected cell type {0:?}")]
    UnexpectedCell(quiethop_crypto::cell::CellType),
    #[error("link frame: {0}")]
    LinkFrame(#[from] quiethop_crypto::link::LinkError),
    #[error("circuit id: {0}")]
    CircId(#[from] quiethop_crypto::circid::CircIdError),
    #[error("link frame named circuit {0:#010x}, which is not this circuit")]
    ForeignCircuit(u32),
    #[error("the relay destroyed the circuit")]
    CircuitDestroyed,
    #[error("unexpected link command {0:?} on an open circuit")]
    UnexpectedLinkCommand(quiethop_crypto::link::LinkCommand),
    #[error("native root certificate store could not be loaded: {0}")]
    NativeRoots(std::io::Error),
}
