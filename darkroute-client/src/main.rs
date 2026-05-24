#![deny(warnings)]
#![forbid(unsafe_code)]

//! SOCKS5 daemon that tunnels CONNECT requests through a 3-hop darkroute circuit.

mod socks5;

use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use darkroute_client::{DarkrouteClient, DarkrouteConfig};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use url::Url;

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

    let mut client = match DarkrouteClient::new(DarkrouteConfig {
        authority_url: authority,
        email,
        password,
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

    let client = Arc::new(Mutex::new(client));

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
