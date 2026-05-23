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
use rustls::{ClientConfig, RootCertStore};
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

use crate::config::RelayConfig;

/// ALPN identifier for the ACME TLS-ALPN-01 challenge (RFC 8737 §3).
/// Connections advertising this ALPN are challenge probes and must be
/// dropped without entering the relay protocol.
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

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
}

pub struct AcmeBundle {
    pub acceptor: TlsAcceptor,
    /// Drives ACME issuance + renewal. Aborting it disables renewals.
    pub driver: tokio::task::JoinHandle<()>,
}

/// Build the inbound TLS acceptor backed by an ACME-managed cert
/// resolver. The returned `driver` MUST stay alive for renewals to run.
pub fn acme_setup(cfg: &RelayConfig) -> Result<AcmeBundle, TlsError> {
    fs::create_dir_all(&cfg.acme_dir)
        .map_err(|e| TlsError::CacheDir(cfg.acme_dir.display().to_string(), e))?;

    let mut state = AcmeConfig::new([cfg.relay_hostname.clone()])
        .contact_push(format!("mailto:{}", cfg.acme_contact_email))
        .cache(DirCache::new(cfg.acme_dir.clone()))
        .directory_lets_encrypt(!cfg.acme_staging)
        .state();

    let rustls_config = state.default_rustls_config();
    let acceptor = TlsAcceptor::from(rustls_config);

    // state must be drained for ACME orders to make progress; this
    // task is the only owner that does that draining.
    let driver = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(result) = state.next().await {
            match result {
                Ok(event) => info!(?event, "acme event"),
                Err(err) => warn!(error = %err, "acme error"),
            }
        }
    });

    Ok(AcmeBundle { acceptor, driver })
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
