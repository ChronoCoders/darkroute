#![deny(warnings)]
#![forbid(unsafe_code)]

mod authority;
mod config;
mod heartbeat;

use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info};

use crate::authority::AuthorityClient;
use crate::config::RelayConfig;

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
    info!(role = %cfg.role, node_id = %cfg.node_id, "config loaded");

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

    // Step 3 — Initialize replay window (placeholder; full implementation in token.rs in a later phase).
    info!(ttl_seconds = cfg.replay_window_ttl, "replay window initialized");

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

    // Step 7 — Begin accepting connections. Connection handling is a stub here;
    // circuit logic lands in a later phase.
    let accept_handle = tokio::spawn(accept_loop(relay_listener, shutdown.clone()));
    let metrics_handle = tokio::spawn(metrics_accept_loop(metrics_listener, shutdown.clone()));

    let _ = authority; // pinned key handle retained for later phases

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

async fn accept_loop(listener: TcpListener, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("relay accept loop shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((_sock, peer)) => {
                    // Phase 2 stub: connection handling lands in a later phase.
                    info!(peer = %peer, "relay connection accepted (stub)");
                }
                Err(e) => {
                    error!(error = %e, "accept failed");
                }
            }
        }
    }
}

async fn metrics_accept_loop(listener: TcpListener, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("metrics accept loop shutting down");
                return;
            }
            res = listener.accept() => match res {
                Ok((_sock, peer)) => {
                    info!(peer = %peer, "metrics connection accepted (stub)");
                }
                Err(e) => {
                    error!(error = %e, "metrics accept failed");
                }
            }
        }
    }
}
