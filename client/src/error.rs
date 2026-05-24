use darkroute_crypto::cell::CellError;
use darkroute_crypto::crypto::CryptoError;

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
    Crypto(#[from] CryptoError),
    #[error("cell: {0}")]
    Cell(#[from] CellError),
    #[error("circuit handshake: unexpected cell type {0:?}")]
    UnexpectedCell(darkroute_crypto::cell::CellType),
    #[error("native root certificate store could not be loaded: {0}")]
    NativeRoots(std::io::Error),
}
