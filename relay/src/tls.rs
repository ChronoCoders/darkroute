//! TLS termination for inbound :443 (rustls-acme) and TLS client for
//! outbound relay-to-relay links (rustls + native roots).
//!
//! The inbound `TlsAcceptor` uses rustls-acme's `default_rustls_config`
//! cert resolver. That resolver answers the TLS-ALPN-01 challenge
//! (RFC 8737) on the same :443 listener, so issuance and renewal need
//! no separate port-80 challenge handler. ACME state and issued certs
//! are persisted under [`RelayConfig::acme_dir`] so a process restart
//! does not trigger fresh enrolment.
//!
//! Outbound connections present `[`RelayConfig::peer_hostnames`]` as
//! SNI and verify against it. There is no skip-verify path.

use std::fs;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::server::Acceptor;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_acme::caches::DirCache;
use rustls_acme::{is_tls_alpn_challenge, AcmeConfig};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{info, warn};

use crate::config::RelayConfig;

/// Connection-fatal at minimum; startup variants are process-fatal.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("acme cache directory {0} could not be created: {1}")]
    CacheDir(String, std::io::Error),
    #[error("native root certificate store could not be loaded: {0}")]
    NativeRoots(std::io::Error),
    #[error("hostname {0:?} is not a valid TLS server name")]
    InvalidServerName(String),
    #[error("tls handshake to {0}: {1}")]
    Handshake(String, std::io::Error),
    #[error("tls accept: {0}")]
    Accept(std::io::Error),
}

pub struct AcmeBundle {
    /// rustls config for normal client traffic. Used when the
    /// ClientHello does NOT advertise the `acme-tls/1` ALPN.
    pub default_config: Arc<ServerConfig>,
    /// rustls config that answers the TLS-ALPN-01 challenge with the
    /// challenge cert resolver, advertising `acme-tls/1` ALPN so LE's
    /// validator accepts the response (RFC 8737 §3). Used when
    /// `is_tls_alpn_challenge(client_hello)` returns true.
    pub challenge_config: Arc<ServerConfig>,
    /// Drives ACME issuance + renewal. Aborting it disables renewals.
    pub driver: tokio::task::JoinHandle<()>,
}

/// Build the two rustls configs needed for inbound TLS: one for real
/// traffic, one for ACME-TLS-ALPN-01 challenges. The caller sniffs the
/// ClientHello via [`accept_routed`] to pick which config completes the
/// handshake. The returned `driver` MUST stay alive for renewals to run.
pub fn acme_setup(cfg: &RelayConfig) -> Result<AcmeBundle, TlsError> {
    fs::create_dir_all(&cfg.acme_dir)
        .map_err(|e| TlsError::CacheDir(cfg.acme_dir.display().to_string(), e))?;

    let mut state = AcmeConfig::new([cfg.relay_hostname.clone()])
        .contact_push(format!("mailto:{}", cfg.acme_contact_email))
        .cache(DirCache::new(cfg.acme_dir.clone()))
        .directory_lets_encrypt(!cfg.acme_staging)
        .state();

    let default_config = state.default_rustls_config();
    let challenge_config = state.challenge_rustls_config();

    let driver = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(result) = state.next().await {
            match result {
                Ok(event) => info!(?event, "acme event"),
                Err(err) => warn!(error = %err, "acme error"),
            }
        }
    });

    Ok(AcmeBundle {
        default_config,
        challenge_config,
        driver,
    })
}

/// Per-connection TLS accept that peeks at the ClientHello, routes
/// ACME-TLS-ALPN-01 probes to the challenge config (which advertises
/// the `acme-tls/1` ALPN required for issuance) and everything else to
/// the default config. Returns `Ok(None)` for challenge connections
/// that completed handshake but must not be processed as real clients.
pub async fn accept_routed(
    tcp: TcpStream,
    default_config: Arc<ServerConfig>,
    challenge_config: Arc<ServerConfig>,
) -> Result<Option<ServerTlsStream<TcpStream>>, TlsError> {
    let lazy = LazyConfigAcceptor::new(Acceptor::default(), tcp);
    let start = lazy.await.map_err(TlsError::Accept)?;
    if is_tls_alpn_challenge(&start.client_hello()) {
        let _ = start.into_stream(challenge_config).await;
        return Ok(None);
    }
    let tls = start
        .into_stream(default_config)
        .await
        .map_err(TlsError::Accept)?;
    Ok(Some(tls))
}

/// Build the shared outbound TLS connector. Verification uses the OS
/// native CA bundle so peer relay certs are trusted iff the system
/// trust store already trusts the issuer (Let's Encrypt for production).
pub fn outbound_connector() -> Result<TlsConnector, TlsError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        // OS bundles occasionally include garbage trailers; the aggregate
        // is still trusted up to what rustls successfully parses.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        let combined = native
            .errors
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(TlsError::NativeRoots(std::io::Error::other(combined)));
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(client_config)))
}

/// TCP-connect then TLS-handshake with `sni`. No skip-verify path.
pub async fn dial_tls(
    connector: &TlsConnector,
    addr: std::net::SocketAddr,
    sni: &str,
) -> Result<ClientTlsStream<TcpStream>, TlsError> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| TlsError::Handshake(format!("tcp connect {addr}"), e))?;
    tcp.set_nodelay(true)
        .map_err(|e| TlsError::Handshake(format!("set_nodelay {addr}"), e))?;
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| TlsError::InvalidServerName(sni.to_string()))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| TlsError::Handshake(format!("tls handshake to {sni} at {addr}"), e))
}
