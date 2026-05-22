#![deny(warnings)]
#![forbid(unsafe_code)]

mod authority;
mod config;
mod heartbeat;
mod metrics;
mod token;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use crate::authority::AuthorityClient;
use crate::config::{RelayConfig, Role};
use crate::token::ReplayWindow;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    // Step 1 — Load and validate config. Any missing/invalid value is fatal.
    let cfg = match RelayConfig::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(error = %e, "config validation failed");
            return ExitCode::from(1);
        }
    };
    info!(
        role = %cfg.role,
        node_id = %cfg.node_id,
        relay_port = cfg.relay_port,
        metrics_port = cfg.metrics_port,
        max_circuits = cfg.max_circuits,
        replay_window_ttl_seconds = cfg.replay_window_ttl,
        allowed_exit_ports = ?cfg.allowed_exit_ports,
        "config loaded"
    );
    if cfg.role == Role::Exit {
        // DECODO_PROXY_URL contains credentials; log only the redacted
        // scheme://host:port form. The full URL stays in cfg for exit
        // dialing and is never serialized to logs.
        if let Some(redacted) = cfg.decodo_proxy_url.as_deref().map(redact_proxy_url) {
            info!(decodo_endpoint = %redacted, "exit proxy configured");
        }
    }

    // Step 2 — Fetch and pin the authority's RSA public key. No retry: a relay
    // that cannot pin the authority key must not start.
    let authority = match AuthorityClient::fetch_and_pin(&cfg.authority_pubkey_url).await {
        Ok(a) => Arc::new(a),
        Err(e) => {
            error!(error = %e, "failed to pin authority public key");
            return ExitCode::from(1);
        }
    };
    info!("authority public key pinned");

    // Step 3 — Initialize the replay window and the metrics registry.
    let replay = Arc::new(ReplayWindow::new(Duration::from_secs(cfg.replay_window_ttl)));
    info!(ttl_seconds = cfg.replay_window_ttl, "replay window initialized");
    metrics::init();

    // Step 4 — Open the relay TCP listener.
    let relay_addr = format!("0.0.0.0:{}", cfg.relay_port);
    let relay_listener = match TcpListener::bind(&relay_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %relay_addr, "failed to bind relay port");
            return ExitCode::from(1);
        }
    };
    info!(addr = %relay_addr, "relay listener bound");

    // Step 5 — Open the metrics listener.
    let metrics_addr = format!("0.0.0.0:{}", cfg.metrics_port);
    let metrics_listener = match TcpListener::bind(&metrics_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %metrics_addr, "failed to bind metrics port");
            return ExitCode::from(1);
        }
    };
    info!(addr = %metrics_addr, "metrics listener bound");

    // Step 6 — Start the heartbeat task.
    let shutdown = Arc::new(Notify::new());
    let hb_handle = heartbeat::spawn(cfg.clone(), shutdown.clone());

    // Step 7 — Begin accepting connections. Every accepted socket runs
    // through token::verify() before any further processing; failure drops
    // the connection without writing anything to the peer.
    let accept_handle = tokio::spawn(accept_loop(
        relay_listener,
        shutdown.clone(),
        authority.clone(),
        replay.clone(),
    ));
    let metrics_handle = tokio::spawn(metrics_accept_loop(metrics_listener, shutdown.clone()));

    match signal::ctrl_c().await {
        Ok(()) => info!("shutdown signal received"),
        Err(e) => error!(error = %e, "signal listener failed"),
    }

    shutdown.notify_waiters();
    let _ = hb_handle.await;
    let _ = accept_handle.await;
    let _ = metrics_handle.await;
    info!("shutdown complete");
    ExitCode::SUCCESS
}

/// Strip credentials from a SOCKS5/HTTP proxy URL, returning
/// `scheme://host[:port]`. Used to keep DECODO_PROXY_URL credentials out of
/// the log stream.
fn redact_proxy_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("");
            match u.port() {
                Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
                None => format!("{}://{}", u.scheme(), host),
            }
        }
        Err(_) => "<unparseable>".to_string(),
    }
}

/// Token-presentation frame format: 32 bytes of m_raw, then `MODULUS_BYTES`
/// bytes of token (the RSA-2048 signature). The frame size is fixed; this
/// is the only request shape the relay accepts on its data port.
const M_RAW_LEN: usize = 32;
const TOKEN_LEN: usize = 256;
const PRESENTATION_LEN: usize = M_RAW_LEN + TOKEN_LEN;
const PRESENTATION_READ_TIMEOUT: Duration = Duration::from_secs(5);

async fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<Notify>,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("relay accept loop shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((sock, peer)) => {
                    let auth = authority.clone();
                    let rep = replay.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(sock, peer, auth, rep).await {
                            // The connection is dropped by returning. We
                            // deliberately never write to the peer; the
                            // relay must not leak which check failed.
                            warn!(peer = %peer, reason = %e, "connection rejected");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "accept failed");
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum HandleError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("read timeout")]
    Timeout,
    #[error("token verification failed: {0}")]
    Token(token::TokenError),
}

async fn handle_connection(
    mut sock: TcpStream,
    peer: SocketAddr,
    authority: Arc<AuthorityClient>,
    replay: Arc<ReplayWindow>,
) -> Result<(), HandleError> {
    sock.set_nodelay(true)?;

    let mut buf = [0u8; PRESENTATION_LEN];
    match tokio::time::timeout(PRESENTATION_READ_TIMEOUT, sock.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(HandleError::Io(e)),
        Err(_) => return Err(HandleError::Timeout),
    }

    let m_raw = &buf[..M_RAW_LEN];
    let token = &buf[M_RAW_LEN..];

    // Token verification is mandatory and runs before anything else. On
    // error we record the reason in the metrics counter and return; the
    // socket closes when this function exits.
    if let Err(e) = token::verify(m_raw, token, authority.pubkey(), &replay) {
        metrics::record_rejected(&e);
        return Err(HandleError::Token(e));
    }
    metrics::record_verified();

    info!(peer = %peer, "token verified");
    Ok(())
}

async fn metrics_accept_loop(listener: TcpListener, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("metrics accept loop shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((sock, _peer)) => {
                    tokio::spawn(async move {
                        if let Err(e) = metrics::serve(sock).await {
                            warn!(error = %e, "metrics request failed");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "metrics accept failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_proxy_url_strips_userinfo() {
        let r = redact_proxy_url("socks5://user:pass@proxy.example.com:1080");
        assert_eq!(r, "socks5://proxy.example.com:1080");
    }

    #[test]
    fn redact_proxy_url_handles_no_port() {
        let r = redact_proxy_url("socks5://user:pass@proxy.example.com");
        assert_eq!(r, "socks5://proxy.example.com");
    }

    #[test]
    fn redact_proxy_url_handles_garbage() {
        assert_eq!(redact_proxy_url("not a url"), "<unparseable>");
    }
}
