#![deny(warnings)]
#![forbid(unsafe_code)]

//! SOCKS5 daemon that tunnels CONNECT requests through a 3-hop QuietHop circuit.

mod socks5;

use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use quiethop_client::{PinnedKey, QuietHopClient, QuietHopConfig};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use url::Url;

/// How often the refresh task wakes. The document's own fresh window decides
/// whether a fetch happens, so this only bounds how late a refresh can be.
const REFRESH_POLL: std::time::Duration = std::time::Duration::from_secs(60);

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // rustls 0.23 panics on first ServerConfig/ClientConfig build without one.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        warn!("rustls crypto provider was already installed");
    }

    let authority = match env::var("AUTHORITY_URL") {
        Ok(v) if !v.is_empty() => match Url::parse(&v) {
            Ok(u) => u,
            Err(e) => {
                error!(error = %e, "AUTHORITY_URL is not a valid URL");
                return ExitCode::from(1);
            }
        },
        _ => {
            error!("AUTHORITY_URL is required");
            return ExitCode::from(1);
        }
    };
    let email = match env::var("CLIENT_EMAIL") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            error!("CLIENT_EMAIL is required");
            return ExitCode::from(1);
        }
    };
    let password = match env::var("CLIENT_PASSWORD") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            error!("CLIENT_PASSWORD is required");
            return ExitCode::from(1);
        }
    };
    let bind = env::var("SOCKS5_BIND").unwrap_or_else(|_| "127.0.0.1:1080".to_string());

    // Registry trust is pinned out of band, so a missing key is fatal rather
    // than a fall back to trusting the transport (SECURITY_MODEL 5.3).
    let pinned = match pinned_keys() {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "QUIETHOP_REGISTRY_PUBKEY is required and must be valid");
            return ExitCode::from(1);
        }
    };
    let threshold = match env::var("QUIETHOP_REGISTRY_THRESHOLD") {
        Ok(v) if !v.is_empty() => match v.parse::<usize>() {
            Ok(n) => n,
            Err(e) => {
                error!(error = %e, "QUIETHOP_REGISTRY_THRESHOLD is not a number");
                return ExitCode::from(1);
            }
        },
        _ => 1,
    };
    let state_dir = match quiethop_client::state::state_dir() {
        Ok(d) => d,
        Err(e) => {
            error!(error = %e, "could not determine the state directory");
            return ExitCode::from(1);
        }
    };
    let require_operator_diversity = match parse_flag("QUIETHOP_REQUIRE_OPERATOR_DIVERSITY") {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "QUIETHOP_REQUIRE_OPERATOR_DIVERSITY must be true or false");
            return ExitCode::from(1);
        }
    };
    // Logged because it decides which guarantee every circuit carries, and a
    // default that silently differs from the operator's intent is worth seeing.
    info!(
        require_operator_diversity,
        pinned_registry_keys = pinned.len(),
        registry_threshold = threshold,
        state_dir = %state_dir.display(),
        "registry and path rules"
    );

    let mut client = match QuietHopClient::new(QuietHopConfig {
        authority_url: authority,
        email,
        password,
        pinned_registry_keys: pinned,
        registry_threshold: threshold,
        state_dir,
        require_operator_diversity,
    }) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "client init failed");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = client.login().await {
        error!(error = %e, "login failed");
        return ExitCode::from(1);
    }
    info!("logged in to authority");

    // Primed once here, never inside a circuit build. A fetch per circuit would
    // tell the authority, by client IP, when this address builds circuits.
    if let Err(e) = client.prime_registry(now_unix()).await {
        error!(error = %e, "registry fetch or verification failed");
        return ExitCode::from(1);
    }
    info!("registry verified");

    let client = Arc::new(Mutex::new(client));

    // Refresh on its own schedule, so no circuit build ever waits on a fetch and
    // the authority sees at most one fetch per fresh window rather than one per
    // circuit. A failed refresh is logged and retried: the document already held
    // stays usable until its valid_until, after which build_path refuses rather
    // than building a path from an expired relay set.
    {
        let client = client.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REFRESH_POLL);
            loop {
                tick.tick().await;
                let outcome = {
                    let mut c = client.lock().await;
                    c.refresh_registry(now_unix()).await
                };
                match outcome {
                    Ok(true) => info!("registry refreshed"),
                    Ok(false) => {}
                    Err(e) => {
                        error!(error = %e, "registry refresh failed, serving the last verified document until it expires")
                    }
                }
            }
        });
    }

    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %bind, "failed to bind socks5 listener");
            return ExitCode::from(1);
        }
    };
    info!(addr = %bind, "socks5 listener bound");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = socks5::serve(sock, client).await {
                warn!(peer = %peer, error = %e, "socks5 session ended");
            }
        });
    }
}

/// Seconds since the Unix epoch.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The pinned registry signing keys, as hex, comma separated.
///
/// Hex because `authority registry-keygen` prints hex, so the operator pins the
/// string the tool gave them.
fn pinned_keys() -> Result<Vec<PinnedKey>, String> {
    let raw = env::var("QUIETHOP_REGISTRY_PUBKEY").map_err(|_| "not set".to_string())?;
    let mut out = Vec::new();
    for piece in raw.split(',') {
        let t = piece.trim();
        if t.is_empty() {
            continue;
        }
        out.push(PinnedKey::from_hex(t).map_err(|e| e.to_string())?);
    }
    if out.is_empty() {
        return Err("no key in the value".to_string());
    }
    Ok(out)
}

fn parse_flag(name: &str) -> Result<bool, String> {
    match env::var(name) {
        Ok(v) if !v.is_empty() => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            other => Err(format!("{other:?} is not a boolean")),
        },
        _ => Ok(false),
    }
}
