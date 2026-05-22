use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct HeartbeatPayload<'a> {
    node_id: &'a str,
    role: String,
    relay_port: u16,
}

/// Spawn the heartbeat task. The HTTP client is constructed by main at
/// startup so client-builder failure is fatal at boot rather than silently
/// disabling heartbeats for the lifetime of the process. The relay API key
/// is sent as a Bearer token and never appears in logs.
pub fn spawn(
    cfg: Arc<RelayConfig>,
    client: reqwest::Client,
    shutdown: Arc<Notify>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Send one heartbeat immediately so the authority marks this relay
        // active on startup, then continue on the configured interval.
        send_one(&client, &cfg).await;
        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    info!("heartbeat task shutting down");
                    return;
                }
                _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
                    send_one(&client, &cfg).await;
                }
            }
        }
    })
}

async fn send_one(client: &reqwest::Client, cfg: &RelayConfig) {
    let payload = HeartbeatPayload {
        node_id: &cfg.node_id,
        role: cfg.role.to_string(),
        relay_port: cfg.relay_port,
    };
    let res = client
        .post(&cfg.authority_heartbeat_url)
        .bearer_auth(&cfg.relay_api_key)
        .json(&payload)
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => debug!(status = %r.status(), "heartbeat ok"),
        Ok(r) => warn!(status = %r.status(), "heartbeat rejected"),
        Err(e) => warn!(error = %e, "heartbeat send failed"),
    }
}
