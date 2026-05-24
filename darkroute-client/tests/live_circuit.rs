//! Live end-to-end integration test against production darkroute.
//!
//! Spawns the SOCKS5 daemon binary against api.darkrouter.com using the
//! test operator account (`test@darkrouter.dev`), then performs an HTTP
//! GET to https://api.ipify.org through the SOCKS5 proxy and asserts the
//! returned public IP matches the Decodo NY exit IP wired to node03.
//!
//! Expected exit IP: 48.44.12.164 (node03.darkrouter.com →
//! Decodo residential US dedicated IP). If Decodo rotates the dedicated
//! IP or node03 swaps to a different upstream, this constant must be
//! updated to match.
//!
//! Gated `#[ignore]` so `cargo test` never runs it; only
//! `cargo test -p darkroute-client -- --ignored` exercises this path.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const EXPECTED_EXIT_IP: &str = "48.44.12.164";
const SOCKS_BIND: &str = "127.0.0.1:11080";
const DAEMON_READY_LOG: &str = "socks5 listener bound";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore]
async fn live_circuit_returns_decodo_exit_ip() {
    let email =
        std::env::var("CLIENT_EMAIL").expect("CLIENT_EMAIL must be set (see client/.env.example)");
    let password = std::env::var("CLIENT_PASSWORD")
        .expect("CLIENT_PASSWORD must be set (see client/.env.example)");
    let authority =
        std::env::var("AUTHORITY_URL").unwrap_or_else(|_| "https://api.darkrouter.com".to_string());

    let bin = env!("CARGO_BIN_EXE_darkroute-client");
    let mut child = Command::new(bin)
        .env("AUTHORITY_URL", authority)
        .env("CLIENT_EMAIL", email)
        .env("CLIENT_PASSWORD", password)
        .env("SOCKS5_BIND", SOCKS_BIND)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn darkroute-client");

    // tracing_subscriber::fmt writes to stdout by default; the daemon's
    // ready marker comes through there.
    let stdout = child.stdout.take().expect("stdout captured");
    let mut lines = BufReader::new(stdout).lines();
    let ready = tokio::time::timeout(STARTUP_TIMEOUT, async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains(DAEMON_READY_LOG) {
                return true;
            }
        }
        false
    })
    .await
    .expect("daemon startup timed out");
    assert!(ready, "daemon never logged its ready marker");

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("socks5h://{SOCKS_BIND}")).expect("proxy url"))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("reqwest client");

    let resp = client
        .get("https://api.ipify.org")
        .send()
        .await
        .expect("ipify request via SOCKS5");
    assert!(
        resp.status().is_success(),
        "ipify status: {}",
        resp.status()
    );
    let body = resp.text().await.expect("ipify body");
    let observed = body.trim();

    let _ = child.kill().await;

    assert_eq!(
        observed, EXPECTED_EXIT_IP,
        "exit IP mismatch — got {observed:?}, expected {EXPECTED_EXIT_IP:?} \
         (node03.darkrouter.com → Decodo NY)"
    );
}
