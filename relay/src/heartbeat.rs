use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use quiethop_crypto::noise::STATIC_KEY_LEN;

use crate::config::RelayConfig;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct HeartbeatPayload<'a> {
    node_id: &'a str,
    role: String,
    relay_port: u16,
    /// This relay's X25519 static public key, hex. The authority compares it
    /// with the one recorded at provisioning time and rejects a mismatch
    /// (SECURITY_MODEL §7.2). Public key material, so sending it discloses
    /// nothing; the private half never leaves the key file.
    static_pubkey: String,
}

/// The authority's response when the offered key is not the provisioned one.
const STATUS_STATIC_PUBKEY_MISMATCH: u16 = 409;

/// Render a public key as hex for the heartbeat body.
pub(crate) fn pubkey_hex(key: &[u8; STATIC_KEY_LEN]) -> String {
    let mut out = String::with_capacity(STATIC_KEY_LEN * 2);
    for b in key {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0F), 16).unwrap_or('0'));
    }
    out
}

/// Spawn the heartbeat task. The HTTP client is constructed by main at
/// startup so client-builder failure is fatal at boot rather than silently
/// disabling heartbeats for the lifetime of the process. The relay API key
/// is sent as a Bearer token and never appears in logs.
pub fn spawn(
    cfg: Arc<RelayConfig>,
    client: reqwest::Client,
    static_pubkey: String,
    shutdown: Arc<Notify>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Send one heartbeat immediately so the authority marks this relay
        // active on startup, then continue on the configured interval.
        send_one(&client, &cfg, &static_pubkey).await;
        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    info!("heartbeat task shutting down");
                    return;
                }
                _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
                    send_one(&client, &cfg, &static_pubkey).await;
                }
            }
        }
    })
}

async fn send_one(client: &reqwest::Client, cfg: &RelayConfig, static_pubkey: &str) {
    let payload = HeartbeatPayload {
        node_id: &cfg.node_id,
        role: cfg.role.to_string(),
        relay_port: cfg.relay_port,
        static_pubkey: static_pubkey.to_string(),
    };
    let res = client
        .post(&cfg.authority_heartbeat_url)
        .bearer_auth(&cfg.relay_api_key)
        .json(&payload)
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => debug!(status = %r.status(), "heartbeat ok"),
        Ok(r) if r.status().as_u16() == STATUS_STATIC_PUBKEY_MISMATCH => {
            // The authority holds a different static key for this node_id, so
            // this relay cannot serve circuits: clients pin the registry key
            // and every handshake would fail. An operator must re-provision or
            // restore the original key file. No key bytes are logged.
            error!(
                node_id = %cfg.node_id,
                status = %r.status(),
                "heartbeat rejected: the authority has a different static public key for this relay"
            );
        }
        Ok(r) => warn!(status = %r.status(), "heartbeat rejected"),
        Err(e) => warn!(error = %e, "heartbeat send failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_hex_is_lowercase_and_full_length() {
        let key = [0xDEu8; STATIC_KEY_LEN];
        let hex = pubkey_hex(&key);
        assert_eq!(hex.len(), STATIC_KEY_LEN * 2);
        assert_eq!(hex, "de".repeat(STATIC_KEY_LEN));
    }

    #[test]
    fn pubkey_hex_round_trips_through_a_decoder() {
        let key: [u8; STATIC_KEY_LEN] = std::array::from_fn(|i| (i * 7 % 256) as u8);
        let hex = pubkey_hex(&key);
        let decoded: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex pair"))
            .collect();
        assert_eq!(decoded, key, "the authority must decode what we send");
    }
}
